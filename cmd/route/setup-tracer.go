package main

import (
	"io"
	"sync/atomic"

	"github.com/gradusp/crispy-route/internal/app"
	"github.com/gradusp/go-platform/app/tracing/ot"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdk "go.opentelemetry.io/otel/sdk/trace"
)

var traceProviderHolder atomic.Value

func setupTracer() error {
	ctx := app.Context()
	traceEnabled, err := app.TraceEnable.Maybe(ctx)
	if err != nil {
		return err
	}
	if !traceEnabled {
		return nil
	}
	var (
		exporter sdk.SpanExporter
		rc       *resource.Resource
	)
	//TODO: позже нужно обфзательно прикрутить реальный экспортер
	if exporter, err = stdouttrace.New(stdouttrace.WithWriter(io.Discard)); err != nil {
		return errors.Wrap(err, "make trace exporter")
	}
	defer func() {
		if exporter != nil {
			_ = exporter.Shutdown(ctx)
		}
	}()
	if rc, err = ot.MakeAppResource(ctx); err != nil {
		return errors.Wrap(err, "make trace resource")
	}
	deps := ot.TraceProviderDeps{
		Resource: rc,
	}
	deps.SpanProcessors = append(deps.SpanProcessors, sdk.NewBatchSpanProcessor(exporter))
	tp := ot.NewAppTraceProvider(ctx, deps)
	traceProviderHolder.Store(tp)
	exporter = nil

	return nil
}

//WhenHaveTracerProvider ...
func WhenHaveTracerProvider(consumer func(tp ot.TracerProvider)) {
	tp, _ := traceProviderHolder.Load().(ot.TracerProvider)
	if tp != nil && consumer != nil {
		consumer(tp)
	}
}
