package config

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_DefaultValues(t *testing.T) {
	const (
		b  ValueBool     = "values/bool"
		s  ValueString   = "values/string"
		ti ValueTime     = "values/time"
		du ValueDuration = "values/duration"
		i  ValueInt      = "values/int"
		u  ValueUInt     = "values/uint"
		f  ValueFloat    = "values/float"
	)

	expected := map[interface{}]interface{}{
		b:  true,
		s:  "string",
		ti: time.Now(),
		du: time.Minute,
		i:  1,
		u:  uint(1),
		f:  1.0,
	}

	opts := make([]Option, 0, len(expected))
	for k, v := range expected {
		opts = append(opts, WithDefValue{Key: fmt.Sprintf("%v", k), Val: v})
	}
	err := InitGlobalConfig(opts...)
	if !assert.NoError(t, err) {
		return
	}
	var (
		rB  bool
		rS  string
		rTI time.Time
		rDU time.Duration
		rI  int
		rU  uint
		rF  float64
		ctx = context.Background()
	)

	rB, err = b.Maybe(ctx)
	if !assert.NoError(t, err) || !assert.Equal(t, expected[b], rB) {
		return
	}

	rS, err = s.Maybe(ctx)
	if !assert.NoError(t, err) || !assert.Equal(t, expected[s], rS) {
		return
	}

	rTI, err = ti.Maybe(ctx)
	if !assert.NoError(t, err) || !assert.Equal(t, expected[ti], rTI) {
		return
	}

	rDU, err = du.Maybe(ctx)
	if !assert.NoError(t, err) || !assert.Equal(t, expected[du], rDU) {
		return
	}

	rI, err = i.Maybe(ctx)
	if !assert.NoError(t, err) || !assert.Equal(t, expected[i], rI) {
		return
	}

	rU, err = u.Maybe(ctx)
	if !assert.NoError(t, err) || !assert.Equal(t, expected[u], rU) {
		return
	}

	rF, err = f.Maybe(ctx)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, expected[f], rF)
}

func Test_Env(t *testing.T) {
	err := os.Setenv("TEST_VALUES_BOOL", "true")
	if !assert.NoError(t, err) {
		return
	}
	err = InitGlobalConfig(WithAcceptEnvironment{EnvPrefix: "TEST"})
	if !assert.NoError(t, err) {
		return
	}
	const (
		b ValueBool = "values/bool"
	)
	var (
		rB bool
	)
	ctx := context.Background()
	rB, err = b.Maybe(ctx)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, true, rB)
}

func Test_Source(t *testing.T) {

	const data = `
values:
   bool: true
   duration: 1s
`

	err := InitGlobalConfig(WithSource{
		Source: bytes.NewBuffer([]byte(data)),
		Type:   "yaml",
	})

	if !assert.NoError(t, err) {
		return
	}
	const (
		b  ValueBool     = "values/bool"
		du ValueDuration = "values/duration"
	)
	ctx := context.Background()
	_, err = b.Maybe(ctx)
	if !assert.NoError(t, err) {
		return
	}
	_, err = du.Maybe(ctx)
	assert.NoError(t, err)
}

/*//
func Test_S(t *testing.T) {


	data := `
logger:
  level: INFO

trace:
  enable: true

metrics:
  enable: true

api-server:
  endpoint: tcp://127.0.0.1:9001
  graceful-shutdown: 30s

`

	err := InitGlobalConfig(WithSource{
		Source: bytes.NewBuffer([]byte(data)),
		Type:   "yaml",
	})

	if !assert.NoError(t, err) {
		return
	}

	const a ValueDuration = "grpc/servers/graceful-shutdown"
	//const a1 ValueString = "services/.0.announcer/endpoint"
	const a1 ValueString = "services/0/announcer/endpoint"
	var b time.Duration

	b, err = a.Maybe(context.Background())
	if !assert.NoError(t, err) {
		return
	}

	var b1 string
	b1, err = a1.Maybe(context.Background())
	if !assert.NoError(t, err) {
		return
	}

	_ = b1
	b += 0

}
*/
