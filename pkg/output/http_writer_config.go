package output

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/pantheon-systems/certinel"
	"github.com/pantheon-systems/certinel/pollwatcher"
	"github.com/pantheon-systems/pauditd/pkg/slog"
	"github.com/spf13/viper"
)

const (
	defaultBufferSize          = 100
	defaultWorkerCount         = 10
	defaultBreakerFailureRatio = 0.05
	defaultCertRefreshInterval = 60 * time.Second
	defaultIdleConnTimeout     = 10 * time.Second
)

type config struct {
	failureRatio      float64
	respBodyTransName string
	traceHeaderName   string
	bufferSize        int
	workerCount       int
	serviceURL        string
	attempts          int
	idleConnTimeout   time.Duration
	debug             bool

	sslEnabled     bool
	clientCertPath string
	clientKeyPath  string
	caCertPath     string
}

func (c config) String() string {
	return fmt.Sprintf(`Using HTTP Writers Output Plugin
		attempts: %d
		url: %s
	  worker_count: %d
		buffer_size: %d
		breaker_failure_ratio %f
		response_body_transformer: %s
		idle_conn_timeout: %s,
		ssl: %s
		ssl.client_cert: %s
		ssl.client_key: %s
		ssl.ca_cert: %s`,
		c.attempts,
		c.serviceURL,
		c.workerCount,
		c.bufferSize,
		c.failureRatio,
		c.respBodyTransName,
		c.idleConnTimeout,
		strconv.FormatBool(c.sslEnabled),
		c.clientCertPath,
		c.clientKeyPath,
		c.caCertPath)
}

func (c config) createTLSConfig(cancel context.CancelFunc) (*tls.Config, error) {
	watcher := pollwatcher.New(c.clientCertPath, c.clientKeyPath, defaultCertRefreshInterval)

	sentinel := certinel.New(watcher, slog.Info, func(err error) {
		slog.Error.Printf("Failed to rotate http writer certificates for TLS: %s", err)
		cancel()
	})

	sentinel.Watch()

	var caCerts *x509.CertPool
	caCerts = x509.NewCertPool()
	caCert, err := ioutil.ReadFile(c.caCertPath)
	caCerts.AppendCertsFromPEM(caCert)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		GetClientCertificate: sentinel.GetClientCertificate,
		RootCAs:              caCerts,
	}, nil
}

func newHTTPWriterConfig(viperConfig *viper.Viper) (*config, error) {
	c := &config{}

	c.attempts = viperConfig.GetInt("output.http.attempts")
	if c.attempts < 1 {
		return nil, fmt.Errorf("Output attempts for http must be at least 1, %v provided", c.attempts)
	}

	c.serviceURL = viperConfig.GetString("output.http.url")
	if c.serviceURL == "" {
		return nil, fmt.Errorf("Output http URL must be set")
	}

	c.workerCount = defaultWorkerCount
	if viperConfig.IsSet("output.http.worker_count") {
		c.workerCount = viperConfig.GetInt("output.http.worker_count")
		if c.workerCount < 1 {
			return nil, fmt.Errorf("Output workers for http must be at least 1, %v provided", c.workerCount)
		}
	}

	c.bufferSize = defaultBufferSize
	if viperConfig.IsSet("output.http.buffer_size") {
		c.bufferSize = viperConfig.GetInt("output.http.buffer_size")
		if c.bufferSize < c.workerCount {
			return nil, fmt.Errorf("Buffer size must be larger than worker count, %v provided", c.bufferSize)
		}
	}

	c.traceHeaderName = ""
	if viperConfig.IsSet("output.http.trace_header_name") {
		c.traceHeaderName = viperConfig.GetString("output.http.trace_header_name")
	}

	// Default is returned in the factory method if value is empty string
	if viperConfig.IsSet("output.http.response_body_transformer") {
		c.respBodyTransName = viperConfig.GetString("output.http.response_body_transformer")
	}

	c.debug = viperConfig.IsSet("output.http.debug") && viperConfig.GetBool("output.http.debug")

	c.failureRatio = defaultBreakerFailureRatio
	if viperConfig.IsSet("output.http.breaker_failure_ratio") {
		c.failureRatio = viperConfig.GetFloat64("output.http.breaker_failure_ratio")
	}

	c.sslEnabled = false
	if viperConfig.IsSet("output.http.ssl.enabled") && viperConfig.GetBool("output.http.ssl.enabled") {
		c.sslEnabled = true
		c.clientCertPath = viperConfig.GetString("output.http.ssl.client_cert")
		c.clientKeyPath = viperConfig.GetString("output.http.ssl.client_key")
		c.caCertPath = viperConfig.GetString("output.http.ssl.ca_cert")

		if c.clientCertPath == "" || c.clientKeyPath == "" || c.caCertPath == "" {
			return nil, fmt.Errorf("SSL is enabled, please specify the required certificates (client_cert, client_key, ca_cert)")
		}
	}

	c.idleConnTimeout = defaultIdleConnTimeout
	if viperConfig.IsSet("output.http.idle_conn_timeout") {
		c.idleConnTimeout = viperConfig.GetDuration("output.http.idle_conn_timeout")
	}

	return c, nil
}
