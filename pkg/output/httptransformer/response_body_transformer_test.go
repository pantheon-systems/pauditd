package httptransformer

import (
	"testing"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

type TestRegisterTransformer struct{}

func (t TestRegisterTransformer) Transform(traceID uuid.UUID, body []byte) ([]byte, error) {
	return nil, nil
}

func TestResponseBodyTransformerRegisterAndDefault(t *testing.T) {
	Register("test", TestRegisterTransformer{})

	_, ok := transformers["test"]
	assert.True(t, ok)

	_, ok = transformers["noop"]
	assert.True(t, ok)
}

func TestResponseBodyTransformGetResponseBodyTransformer(t *testing.T) {
	Register("test2", TestRegisterTransformer{})

	transformer := GetResponseBodyTransformer("test2")
	assert.IsType(t, TestRegisterTransformer{}, transformer)

	// with empty string we get default
	transformer = GetResponseBodyTransformer("")
	assert.IsType(t, NoopTransformer{}, transformer)
}

func TestNoopTransformerTransform(t *testing.T) {
	transformer := NoopTransformer{}

	traceID, _ := uuid.FromString("cd4702b3-4763-11e8-917a-0242ac110002")
	body := []byte("test string")
	resultBody, _ := transformer.Transform(traceID, body)

	assert.Equal(t, body, resultBody)
}
