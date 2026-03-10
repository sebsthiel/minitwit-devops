package monitoring

import "github.com/prometheus/client_golang/prometheus"

var HttpRequests = prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "minitwit_http_requests_total",
        Help: "Total HTTP requests",
    },
    []string{"method", "endpoint"},
)

var HttpResponses = prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "minitwit_http_responses_total",
        Help: "Total HTTP responses",
    },
    []string{"method", "endpoint", "status"},
)

var HttpDuration = prometheus.NewHistogramVec(
    prometheus.HistogramOpts{
        Name:    "minitwit_http_request_duration_seconds",
        Help:    "HTTP request duration",
        Buckets: prometheus.DefBuckets,
    },
    []string{"method", "endpoint"},
)

func Init() {
    prometheus.MustRegister(HttpRequests)
    prometheus.MustRegister(HttpResponses)
    prometheus.MustRegister(HttpDuration)
}