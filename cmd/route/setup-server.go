package main

import (
	"context"
	"net/http"
	"net/http/pprof"

	"github.com/gradusp/crispy-route/internal/api/route"
	tracing "github.com/gradusp/go-platform/app/tracing/ot"
	"github.com/gradusp/go-platform/server"
	"github.com/gradusp/go-platform/server/interceptors"
	serverPrometheusMetrics "github.com/gradusp/go-platform/server/metrics/prometheus"
	serverTracing "github.com/gradusp/go-platform/server/trace/ot"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func pprofHandler() http.Handler { //TODO: Maybe it`s better to place 'pprofHandler' onto GO-PLATFORM
	const (
		pprofs = "/pprof"
	)
	r := http.NewServeMux()

	r.HandleFunc(pprofs+"/index", pprof.Index)
	r.HandleFunc(pprofs+"/profile", pprof.Profile)
	r.HandleFunc(pprofs+"/symbol", pprof.Symbol)
	r.HandleFunc(pprofs+"/trace", pprof.Trace)
	r.HandleFunc(pprofs+"/cmdline", pprof.Cmdline)

	r.Handle(pprofs+"/goroutine", pprof.Handler("goroutine"))
	r.Handle(pprofs+"/threadcreate", pprof.Handler("threadcreate"))
	r.Handle(pprofs+"/mutex", pprof.Handler("mutex"))
	r.Handle(pprofs+"/heap", pprof.Handler("heap"))
	r.Handle(pprofs+"/block", pprof.Handler("block"))
	r.Handle(pprofs+"/allocs", pprof.Handler("allocs"))

	return r
}

func setupServer(ctx context.Context) (*server.APIServer, error) {
	service := route.NewRouteService(ctx)
	doc, err := route.GetSwaggerDocs()
	if err != nil {
		return nil, err
	}

	opts := []server.APIServerOption{
		server.WithServices(service),
		server.WithDocs(doc, ""),
	}

	//если есть регистр Прометеуса то - подклчим метрики
	WhenHaveMetricsRegistry(func(reg *prometheus.Registry) {
		pm := serverPrometheusMetrics.NewMetrics(
			serverPrometheusMetrics.WithSubsystem("grpc"),
			serverPrometheusMetrics.WithNamespace("server"),
		)

		if err = reg.Register(pm); err != nil {
			return
		}

		recovery := interceptors.NewRecovery(
			interceptors.RecoveryWithObservers(pm.PanicsObserver()), //подключаем prometheus счетчик паник
		)
		//подключаем prometheus метрики
		opts = append(opts, server.WithRecovery(recovery))
		opts = append(opts, server.WithStatsHandlers(pm.StatHandlers()...))

		promHandler := promhttp.InstrumentMetricHandler(
			reg,
			promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
		)
		//экспанируем метрики через '/metrics' обработчик
		opts = append(opts, server.WithHttpHandler("/metrics", promHandler))
	})
	//если есть Tracer то - подклчим его к серверу
	WhenHaveTracerProvider(func(tp tracing.TracerProvider) {
		tracer := serverTracing.NewGRPCServerTracer(serverTracing.WithTracerProvider(tp))
		opts = append(opts,
			server.WithStreamInterceptors(tracer.TraceStreamCalls),
			server.WithUnaryInterceptors(tracer.TraceUnaryCalls),
		)
	})
	if err != nil {
		return nil, err
	}
	opts = append(opts, server.WithHttpHandler("/debug", pprofHandler()))
	return server.NewAPIServer(opts...)
}
