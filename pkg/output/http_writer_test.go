package output

import (
	"context"
	"io/ioutil"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/pantheon-systems/pauditd/pkg/metric"
	"github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"gopkg.in/alexcesaro/statsd.v2"
)

var transformerFunctionWasCalled = false

type TestTransformer struct{}

func (t TestTransformer) Transform(traceID uuid.UUID, body []byte) ([]byte, error) {
	transformerFunctionWasCalled = true
	return body, nil
}

func TestHTTPWriter_newHttpWriter(t *testing.T) {
	// attempts error
	c := viper.New()
	c.Set("output.http.stats.enabled", false)
	c.Set("output.http.attempts", 0)
	w, err := newHTTPWriter(c)
	assert.EqualError(t, err, "Output attempts for http must be at least 1, 0 provided")
	assert.Nil(t, w)

	// url error
	c = viper.New()
	c.Set("output.http.stats.enabled", false)
	c.Set("output.http.url", "")
	c.Set("output.http.attempts", 1)
	w, err = newHTTPWriter(c)
	assert.EqualError(t, err, "Output http URL must be set")
	assert.Nil(t, w)

	// worker count error
	c = viper.New()
	c.Set("output.http.stats.enabled", false)
	c.Set("output.http.url", "http://someurl.com")
	c.Set("output.http.attempts", 1)
	c.Set("output.http.worker_count", 0)
	w, err = newHTTPWriter(c)
	assert.EqualError(t, err, "Output workers for http must be at least 1, 0 provided")
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
	metric.Configure(cfg)
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

	statsMock, _ := statsd.New(statsd.Mute(true))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		receivedPost = true
		body, _ = ioutil.ReadAll(r.Body)
		byteCount = r.ContentLength
		traceID = r.Header.Get("X-TRACE-ID")
		wg.Done()
	})
	go func() {
		http.ListenAndServe(":8888", nil)
	}()

	testTransformer := TestTransformer{}

	msgChannel := make(chan *messageTransport, 1)
	msg := []byte("test string")
	writer := &HTTPWriter{
		url:                     "http://localhost:8888",
		client:                  &http.Client{},
		messages:                msgChannel,
		ResponseBodyTransformer: testTransformer,
		traceHeaderName:         "X-TRACE-ID",
	}

	transport := &messageTransport{
		message: msg,
		timer:   statsMock.NewTiming(),
	}

	msgChannel <- transport
	go writer.Process(context.Background())

	if waitTimeout(wg, 15*time.Second) {
		assert.FailNow(t, "Did not recieve call to test service within timeout")
	}

	assert.NotEmpty(t, traceID)
	assert.NotNil(t, uuid.FromStringOrNil(traceID))
	assert.True(t, transformerFunctionWasCalled)
	assert.True(t, receivedPost)
	assert.Equal(t, int64(11), byteCount)
	assert.Equal(t, msg, body)
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
