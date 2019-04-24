package httptransformer

import (
	"github.com/satori/go.uuid"
	"github.com/spf13/viper"
)

// ResponseBodyTransformer is an interface that allows different
// preparations to happen on the body of the message before
// it is sent (STORED AS A SINGLETON)
type ResponseBodyTransformer interface {
	// Transform takes the result in byte array and returns
	// a transformed byte array or error
	Transform(uuid.UUID, []byte) ([]byte, error)
}

type tansformerConstructor func(*viper.Viper) ResponseBodyTransformer

var transformers = map[string]tansformerConstructor{}

func init() {
	Register("noop", NewNoopTransformer)
}

// Register saves a name and trasformer pair for use with the factory
func Register(name string, transformer func(*viper.Viper) ResponseBodyTransformer) {
	transformers[name] = transformer
}

// GetResponseBodyTransformer returns a transformer by name
func GetResponseBodyTransformer(name string, config *viper.Viper) ResponseBodyTransformer {
	if name == "" {
		// noop is the default transformer
		name = "noop"
	}

	return transformers[name](config)
}

// NoopTransformer is the concrete type for ResponseBodyTransformer that
// does nothing (DEFUALT)
type NoopTransformer struct{}

// NewNoopTransformer creates new transformer that does nothing
func NewNoopTransformer(config *viper.Viper) ResponseBodyTransformer {
	return &NoopTransformer{}
}

// Transform is a noop for the NoopTransformer
func (t NoopTransformer) Transform(traceID uuid.UUID, body []byte) ([]byte, error) {
	return body, nil
}
