package main

import (
	"sync/atomic"

	"github.com/gradusp/crispy-route/internal/app"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

var appPromRegistry atomic.Value

func setupMetrics() error {
	ctx := app.Context()
	enabled, err := app.MetricsEnable.Maybe(ctx)
	if err != nil {
		return err
	}
	var reg *prometheus.Registry
	if enabled {
		reg = prometheus.NewRegistry()
		//добавим по умолчанию гошные + системные коллекторы
		cols := []prometheus.Collector{
			collectors.NewBuildInfoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
			collectors.NewGoCollector(),
		}
		for _, c := range cols {
			if err = reg.Register(c); err != nil {
				return err
			}
		}
	}
	appPromRegistry.Store(reg)
	return nil
}

//WhenHaveMetricsRegistry ...
func WhenHaveMetricsRegistry(f func(reg *prometheus.Registry)) {
	r, _ := appPromRegistry.Load().(*prometheus.Registry)
	if r != nil && f != nil {
		f(r)
	}
}
