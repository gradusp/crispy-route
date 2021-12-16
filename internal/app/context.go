package app

import (
	"context"
	"sync/atomic"
)

//Context context of application
func Context() context.Context {
	if t, ok := appCtxHolder.Load().(context.Context); ok {
		return t
	}
	return context.Background()
}

//SetContext set app context
func SetContext(c context.Context) {
	appCtxHolder.Store(c)
}

var (
	appCtxHolder atomic.Value
)
