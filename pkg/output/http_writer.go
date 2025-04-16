package output

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"

	"log/slog"

	"github.com/pantheon-systems/pauditd/pkg/metric"
	"github.com/pantheon-systems/pauditd/pkg/output/httptransformer"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"github.com/streadway/handy/breaker"
	statsd "gopkg.in/alexcesaro/statsd.v2"
)

const (
	maxBuffErrCount = 10
)

// HTTPWriter is the class that encapsulates the http output plugin
type HTTPWriter struct {
	url                     string
	messages                chan *messageTransport
	client                  *http.Client
	wg                      *sync.WaitGroup
	ResponseBodyTransformer httptransformer.ResponseBodyTransformer
	debug                   bool
	traceHeaderName         string
	workerShutdownSignals   chan struct{}
	cancelFunc              context.CancelFunc
	buffErrCount            int
}

type messageTransport struct {
	message []byte
	timer   statsd.Timing
}

func init() {
	register("http", newHTTPWriter)
}

func (w *HTTPWriter) Write(p []byte) (n int, err error) {
	latencyTimer := metric.GetClient().NewTiming()

	// this defered method catches the panic on write to the channel
	// then handles shutdown gracefully
	defer func() {
		if r := recover(); r != nil {
			_, ok := r.(error)
			if !ok {
				slog.Error(fmt.Sprintf("pkg: %v", r))
			}
			w.cancelFunc()
			slog.Info("Waiting for goroutines to complete")
			w.wg.Wait()
			slog.Info("Goroutines completed")
			os.Exit(0)
		}
	}()

	metric.GetClient().Increment("http_writer.total_messages")

	transport := &messageTransport{
		message: p,
		timer:   latencyTimer,
	}

	bytesSent := len(p)
	select {
	case w.messages <- transport:
		w.buffErrCount = 0
	default:
		slog.Error("Buffer full or closed, messages dropped")
		metric.GetClient().Increment("http_writer.dropped_messages")

		// Exit the pod if the error persists
		if w.buffErrCount > maxBuffErrCount {
			os.Exit(1)
		}
		w.buffErrCount++
	}

	return bytesSent, nil
}

// Process blocks and listens for messages in the channel
func (w *HTTPWriter) Process(ctx context.Context) {
	for {
		select {
		case <-w.workerShutdownSignals:
			fmt.Println("Worker shutting down!")
			w.wg.Done()
			return
		case transport := <-w.messages:
			if transport == nil {
				continue
			}

			traceID := uuid.NewV1()
			body, err := w.ResponseBodyTransformer.Transform(traceID, transport.message)
			if err != nil || body == nil {
				slog.Error(fmt.Sprintf("Message transformation failed: %v", err))
				continue
			}
			if w.debug {
				slog.Info("http_writer.process",
					"trace_id", traceID,
					"original", strings.TrimSpace(string(transport.message)),
					"transformed", string(body),
					"event", "http.write",
					"component", "http_writer",
				)
			}
			payloadReader := bytes.NewReader(body)

			req, err := http.NewRequest(http.MethodPost, w.url, payloadReader)
			if err != nil {
				slog.Error(fmt.Sprintf("HTTPWriter.Process failed to create HTTP request: %v", err))
				continue
			}

			if w.traceHeaderName != "" {
				req.Header.Add(w.traceHeaderName, traceID.String())
				slog.Info("http_writer.header_injection",
					"event", "header.inject",
					"component", "http_writer",
					"trace_id", traceID,
					"header_name", w.traceHeaderName,
					"header_value", traceID.String(),
				)
			}

			resp, err := w.client.Do(req.WithContext(ctx))
			if err != nil {
				slog.Error(fmt.Sprintf("HTTPWriter.Process failed to send HTTP request: %v", err))
				metric.GetClient().Increment("http_writer.request_error.count")
				continue
			}

			metric.GetClient().Increment(fmt.Sprintf("http_code.%d", resp.StatusCode))
			if err := resp.Body.Close(); err != nil {
				slog.Error("Failed to close response body", "error", err)
			}

			transport.timer.Send("http_writer.latency")
		}
	}
}

func newHTTPWriter(config *viper.Viper) (*AuditWriter, error) {
	var err error

	writerConfig, err := newHTTPWriterConfig(config)
	if err != nil {
		return nil, err
	}

	if writerConfig.debug {
		slog.Info(fmt.Sprintf("%v", writerConfig))
	}

	queue := make(chan *messageTransport, writerConfig.bufferSize)
	workerShutdownSignals := make(chan struct{}, writerConfig.workerCount)

	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	go func() {
		select {
		case v := <-signals:
			slog.Info(fmt.Sprintf("Received signal %v\n", v))
			close(queue)
			cancel()
		case <-ctx.Done():
			slog.Info("cancel() called! Shutting down")
		}
		slog.Info(fmt.Sprintf("Shutting down %d workers...\n", writerConfig.workerCount))
		for i := 0; i < writerConfig.workerCount; i++ {
			workerShutdownSignals <- struct{}{}
		}
	}()

	transport := &http.Transport{
		IdleConnTimeout: writerConfig.idleConnTimeout,
	}
	if writerConfig.sslEnabled {
		tlsConfig, err := writerConfig.createTLSConfig(cancel)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}

	breakerTransport := breaker.Transport(
		breaker.NewBreaker(writerConfig.failureRatio),
		breaker.DefaultResponseValidator,
		transport)

	httpClient := &http.Client{
		Transport: breakerTransport,
	}

	wg := &sync.WaitGroup{}
	wg.Add(writerConfig.workerCount)

	writer := &HTTPWriter{
		url:                     writerConfig.serviceURL,
		messages:                queue,
		client:                  httpClient,
		wg:                      wg,
		ResponseBodyTransformer: httptransformer.GetResponseBodyTransformer(writerConfig.respBodyTransName, config),
		debug:                   writerConfig.debug,
		traceHeaderName:         writerConfig.traceHeaderName,
		workerShutdownSignals:   workerShutdownSignals,
		cancelFunc:              cancel,
		buffErrCount:            0,
	}

	for i := 0; i < writerConfig.workerCount; i++ {
		go writer.Process(ctx)
	}

	return NewAuditWriter(writer, writerConfig.attempts), nil
}
