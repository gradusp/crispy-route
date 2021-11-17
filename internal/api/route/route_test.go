package route

import (
	"bytes"
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_ExecExternal(t *testing.T) {
	ctx := context.Background()
	srv := NewRouteService(ctx).(*routeService)
	out := bytes.NewBuffer(nil)
	ec, err := srv.execExternal(ctx, out, "echo", "OK")
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Equal(t, 0, ec) {
		return
	}
	if !assert.Equal(t, "OK\n", out.String()) {
		return
	}
	ctx2, c := context.WithTimeout(context.Background(), 1*time.Second)
	defer c()
	_, err = srv.execExternal(ctx2, out, "sleep", "10")
	assert.Equal(t, context.DeadlineExceeded, err)
}

//parseRoutes

func Test_parseRoutes(t *testing.T) {

	const data = `1.2.1.1   dev  tun10
   -1.11.1.2 dev tun10

  1.11.1.3 dev tun10

1.11.256.4 dev tun10
1.11.255.5 dev tun10

1.11.255.6 dev tun10-
1.11.255.7 dev tun10`

	expected := []string{"1.2.1.1:10", "1.11.1.3:10", "1.11.255.5:10", "1.11.255.7:10"}
	sort.Strings(expected)
	ctx := context.Background()
	srv := NewRouteService(ctx).(*routeService)
	r := srv.parseRoutes([]byte(data))
	assert.Equal(t, expected, r)
}
