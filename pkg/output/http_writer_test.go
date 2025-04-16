package output

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pantheon-systems/pauditd/pkg/metric"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var transformerFunctionWasCalled = false

type TestTransformer struct{}

func (t TestTransformer) Transform(_ uuid.UUID, body []byte) ([]byte, error) {
	transformerFunctionWasCalled = true
	return body, nil
}

func TestHTTPWriter_newHttpWriter(t *testing.T) {
	// attempts error
	c := viper.New()
	c.Set("output.http.stats.enabled", false)
	c.Set("output.http.attempts", 0)
	w, err := newHTTPWriter(c)
	assert.EqualError(t, err, "output attempts for http must be at least 1, 0 provided")
	assert.Nil(t, w)

	// url error
	c = viper.New()
	c.Set("output.http.stats.enabled", false)
	c.Set("output.http.url", "")
	c.Set("output.http.attempts", 1)
	w, err = newHTTPWriter(c)
	assert.EqualError(t, err, "output http URL must be set")
	assert.Nil(t, w)

	// worker count error
	c = viper.New()
	c.Set("output.http.stats.enabled", false)
	c.Set("output.http.url", "http://someurl.com")
	c.Set("output.http.attempts", 1)
	c.Set("output.http.worker_count", 0)
	w, err = newHTTPWriter(c)
	assert.EqualError(t, err, "output workers for http must be at least 1, 0 provided")
	assert.Nil(t, w)

	// All good no ssl
	c = viper.New()
	c.Set("output.http.stats.enabled", false)
	c.Set("output.http.url", "http://someurl.com")
	c.Set("output.http.attempts", 1)
	c.Set("output.http.worker_count", 2)
	c.Set("output.http.buffer_size", 4)
	c.Set("output.http.ssl.enabled", false)
	w, err = newHTTPWriter(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &HTTPWriter{}, w.w)

	// All good no ssl (dont set)
	c = viper.New()
	c.Set("output.http.stats.enabled", false)
	c.Set("output.http.mute_stats", true)
	c.Set("output.http.url", "http://someurl.com")
	c.Set("output.http.attempts", 1)
	c.Set("output.http.worker_count", 2)
	c.Set("output.http.buffer_size", 4)
	w, err = newHTTPWriter(c)
	assert.Nil(t, err)
	assert.NotNil(t, w)
	assert.IsType(t, &HTTPWriter{}, w.w)
	assert.Equal(t, 1, w.attempts)

	// ssl no certs error
	c = viper.New()
	c.Set("output.http.stats.enabled", false)
	c.Set("output.http.url", "http://someurl.com")
	c.Set("output.http.attempts", 1)
	c.Set("output.http.worker_count", 2)
	c.Set("output.http.ssl.enabled", true)
	c.Set("output.http.buffer_size", 4)
	w, err = newHTTPWriter(c)
	assert.EqualError(t, err, "SSL is enabled, please specify the required certificates (client_cert, client_key, ca_cert)")
	assert.Nil(t, w)
}

func TestHTTPWriter_write(t *testing.T) {
	msgChannel := make(chan *messageTransport, 1)

	cfg := viper.New()
	cfg.Set("metrics.enabled", false)
	if err := metric.Configure(cfg); err != nil {
		t.Errorf("Failed to configure metric: %v", err)
	}
	writer := &HTTPWriter{
		messages: msgChannel,
	}

	msg := []byte("test string")
	result, err := writer.Write(msg)
	assert.Nil(t, err)
	assert.Equal(t, len(msg), result)

	resultMsg := <-msgChannel
	assert.Equal(t, "test string", string(resultMsg.message))
}

func TestHTTPWriter_process(t *testing.T) {
	receivedPost := false
	var body []byte
	var byteCount int64
	var traceID string
	var mu sync.Mutex // Guard shared variables

	// Configure metrics
	cfg := viper.New()
	cfg.Set("metrics.enabled", false)
	if err := metric.Configure(cfg); err != nil {
		t.Fatalf("Failed to configure metrics: %v", err)
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)

	// Start the test HTTP server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		mu.Lock()
		defer mu.Unlock()
		receivedPost = true
		body, _ = io.ReadAll(r.Body)
		byteCount = r.ContentLength
		traceID = r.Header.Get("X-TRACE-ID")
	}))
	defer testServer.Close()

	// Set up HTTPWriter
	msg := []byte("test string")
	msgChannel := make(chan *messageTransport, 1)
	writer := &HTTPWriter{
		url:                     testServer.URL,
		client:                  &http.Client{},
		messages:                msgChannel,
		ResponseBodyTransformer: TestTransformer{},
		traceHeaderName:         "X-TRACE-ID",
		debug:                   true,
		workerShutdownSignals:   make(chan struct{}),
		wg:                      &sync.WaitGroup{},
	}

	// Start processing
	go writer.Process(context.Background())

	// Send message
	msgChannel <- &messageTransport{
		message: msg,
		timer:   metric.GetClient().NewTiming(),
	}

	// Wait for request to be received
	if waitTimeout(wg, 10*time.Second) {
		t.Fatal("Timed out waiting for HTTP handler to complete")
	}

	// Assert results
	mu.Lock()
	defer mu.Unlock()
	t.Logf("Received 'X-TRACE-ID' header in handler: %s", traceID)

	assert.NotEmpty(t, traceID, "Trace ID should not be empty")
	assert.True(t, transformerFunctionWasCalled, "Transformer function should have been called")
	assert.True(t, receivedPost, "Server should have received the request")
	assert.Equal(t, int64(11), byteCount, "Byte count should match")
	assert.Equal(t, msg, body, "Body should match message")
}

func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}
