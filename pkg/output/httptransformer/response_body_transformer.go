package httptransformer

import "github.com/satori/go.uuid"

// ResponseBodyTransformer is an interface that allows different
// preparations to happen on the body of the message before
// it is sent (STORED AS A SINGLETON)
type ResponseBodyTransformer interface {
	// Transform takes the result in byte array and returns
	// a transformed byte array or error
	Transform(uuid.UUID, []byte) ([]byte, error)
}

var transformers = map[string]ResponseBodyTransformer{}

func init() {
	Register("noop", NoopTransformer{})
}

// Register saves a name and trasformer pair for use with the factory
func Register(name string, transformer ResponseBodyTransformer) {
	transformers[name] = transformer
}

// GetResponseBodyTransformer returns a transformer by name
func GetResponseBodyTransformer(name string) ResponseBodyTransformer {
	if name == "" {
		// noop is the default transformer
		name = "noop"
	}

	return transformers[name]
}

// NoopTransformer is the concrete type for ResponseBodyTransformer that
// does nothing (DEFUALT)
type NoopTransformer struct{}

// Transform is a noop for the NoopTransformer
func (t NoopTransformer) Transform(traceID uuid.UUID, body []byte) ([]byte, error) {
	return body, nil
}
