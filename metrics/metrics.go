package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Count of HTTP-requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	grpcRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_requests_total",
			Help: "Count of gRPC-requests",
		},
		[]string{"service", "method", "status"},
	)
)

func RegisterMetrics() {
	prometheus.MustRegister(httpRequests, grpcRequests)
}

func PrometheusHandler() http.Handler {
	return promhttp.Handler()
}
