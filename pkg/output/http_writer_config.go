package output

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/pantheon-systems/certinel"
	"github.com/pantheon-systems/certinel/pollwatcher"
	"github.com/pantheon-systems/pauditd/pkg/logger"
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

	sentinel := certinel.New(watcher, logger.GetLoggerWrapper(), func(err error) {
		logger.Error("Failed to rotate http writer certificates for TLS: %s", err)
		cancel()
	})

	sentinel.Watch()

	caCerts := x509.NewCertPool()
	caCert, err := os.ReadFile(c.caCertPath)
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

	if err := setAttempts(viperConfig, c); err != nil {
		return nil, err
	}

	if err := setServiceURL(viperConfig, c); err != nil {
		return nil, err
	}

	if err := setWorkerCount(viperConfig, c); err != nil {
		return nil, err
	}

	if err := setBufferSize(viperConfig, c); err != nil {
		return nil, err
	}

	setTraceHeaderName(viperConfig, c)
	setResponseBodyTransformer(viperConfig, c)
	setDebug(viperConfig, c)
	setFailureRatio(viperConfig, c)

	if err := setSSLConfig(viperConfig, c); err != nil {
		return nil, err
	}

	setIdleConnTimeout(viperConfig, c)

	return c, nil
}

func setAttempts(viperConfig *viper.Viper, c *config) error {
	c.attempts = viperConfig.GetInt("output.http.attempts")
	if c.attempts < 1 {
		return fmt.Errorf("output attempts for http must be at least 1, %v provided", c.attempts)
	}
	return nil
}

func setServiceURL(viperConfig *viper.Viper, c *config) error {
	c.serviceURL = viperConfig.GetString("output.http.url")
	if c.serviceURL == "" {
		return fmt.Errorf("output http URL must be set")
	}
	return nil
}

func setWorkerCount(viperConfig *viper.Viper, c *config) error {
	c.workerCount = defaultWorkerCount
	if viperConfig.IsSet("output.http.worker_count") {
		c.workerCount = viperConfig.GetInt("output.http.worker_count")
		if c.workerCount < 1 {
			return fmt.Errorf("output workers for http must be at least 1, %v provided", c.workerCount)
		}
	}
	return nil
}

func setBufferSize(viperConfig *viper.Viper, c *config) error {
	c.bufferSize = defaultBufferSize
	if viperConfig.IsSet("output.http.buffer_size") {
		c.bufferSize = viperConfig.GetInt("output.http.buffer_size")
		if c.bufferSize < c.workerCount {
			return fmt.Errorf("buffer size must be larger than worker count, %v provided", c.bufferSize)
		}
	}
	return nil
}

func setTraceHeaderName(viperConfig *viper.Viper, c *config) {
	if viperConfig.IsSet("output.http.trace_header_name") {
		c.traceHeaderName = viperConfig.GetString("output.http.trace_header_name")
	}
}

func setResponseBodyTransformer(viperConfig *viper.Viper, c *config) {
	if viperConfig.IsSet("output.http.response_body_transformer") {
		c.respBodyTransName = viperConfig.GetString("output.http.response_body_transformer")
	}
}

func setDebug(viperConfig *viper.Viper, c *config) {
	c.debug = viperConfig.IsSet("output.http.debug") && viperConfig.GetBool("output.http.debug")
}

func setFailureRatio(viperConfig *viper.Viper, c *config) {
	c.failureRatio = defaultBreakerFailureRatio
	if viperConfig.IsSet("output.http.breaker_failure_ratio") {
		c.failureRatio = viperConfig.GetFloat64("output.http.breaker_failure_ratio")
	}
}

func setSSLConfig(viperConfig *viper.Viper, c *config) error {
	c.sslEnabled = false
	if viperConfig.IsSet("output.http.ssl.enabled") && viperConfig.GetBool("output.http.ssl.enabled") {
		c.sslEnabled = true
		c.clientCertPath = viperConfig.GetString("output.http.ssl.client_cert")
		c.clientKeyPath = viperConfig.GetString("output.http.ssl.client_key")
		c.caCertPath = viperConfig.GetString("output.http.ssl.ca_cert")

		if c.clientCertPath == "" || c.clientKeyPath == "" || c.caCertPath == "" {
			return fmt.Errorf("SSL is enabled, please specify the required certificates (client_cert, client_key, ca_cert)")
		}
	}
	return nil
}

func setIdleConnTimeout(viperConfig *viper.Viper, c *config) {
	c.idleConnTimeout = defaultIdleConnTimeout
	if viperConfig.IsSet("output.http.idle_conn_timeout") {
		c.idleConnTimeout = viperConfig.GetDuration("output.http.idle_conn_timeout")
	}
}
