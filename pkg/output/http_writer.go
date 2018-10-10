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

	"github.com/pantheon-systems/go-audit/pkg/metric"
	"github.com/pantheon-systems/go-audit/pkg/output/httptransformer"
	"github.com/pantheon-systems/go-audit/pkg/slog"
	"github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"github.com/streadway/handy/breaker"
	"gopkg.in/alexcesaro/statsd.v2"
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
				slog.Error.Printf("pkg: %v", r)
			}
			slog.Info.Println("Waiting for goroutines to complete")
			w.wg.Wait()
			slog.Info.Println("Goroutines completed")
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
	default:
		slog.Error.Printf("Buffer full or closed, messages dropped")
		metric.GetClient().Increment("http_writer.dropped_messages")
	}

	return bytesSent, nil
}

// Process blocks and listens for messages in the channel
func (w *HTTPWriter) Process(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			w.wg.Done()
			return
		case transport := <-w.messages:
			if transport == nil {
				continue
			}

			traceID, err := uuid.NewV1()
			if err != nil {
				slog.Error.Printf("Could not generate UUID: %s", err.Error())
			}

			if w.debug {
				slog.Info.Printf("{ trace_id: \"%s\", msg: %s }", traceID, strings.TrimSuffix(string(transport.message), "\n"))
			}

			body, err := w.ResponseBodyTransformer.Transform(traceID, transport.message)
			if err != nil || body == nil {
				continue
			}
			if w.debug {
				slog.Info.Printf(string(body))
			}
			payloadReader := bytes.NewReader(body)

			req, err := http.NewRequest(http.MethodPost, w.url, payloadReader)
			if err != nil {
				slog.Error.Printf("HTTPWriter.Process could not create new request: %s", err.Error())
				continue
			}

			if w.traceHeaderName != "" {
				req.Header.Add(w.traceHeaderName, traceID.String())
			}

			resp, err := w.client.Do(req.WithContext(ctx))
			if err != nil {
				slog.Error.Printf("HTTPWriter.Process could not send request: %s", err.Error())
				continue
			}

			metric.GetClient().Increment(fmt.Sprintf("http_code.%d", resp.StatusCode))
			resp.Body.Close()

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
		slog.Info.Print(writerConfig)
	}

	transport := &http.Transport{}
	if writerConfig.sslEnabled {
		tlsConfig, err := writerConfig.createTLSConfig()
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

	queue := make(chan *messageTransport, writerConfig.bufferSize)

	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	go func() {
		select {
		case <-signals:
			close(queue)
			cancel()
		case <-ctx.Done():
		}
	}()

	wg := &sync.WaitGroup{}
	wg.Add(writerConfig.workerCount)

	writer := &HTTPWriter{
		url:      writerConfig.serviceURL,
		messages: queue,
		client:   httpClient,
		wg:       wg,
		ResponseBodyTransformer: httptransformer.GetResponseBodyTransformer(writerConfig.respBodyTransName),
		debug:           writerConfig.debug,
		traceHeaderName: writerConfig.traceHeaderName,
	}

	for i := 0; i < writerConfig.workerCount; i++ {
		go writer.Process(ctx)
	}

	return NewAuditWriter(writer, writerConfig.attempts), nil
}
