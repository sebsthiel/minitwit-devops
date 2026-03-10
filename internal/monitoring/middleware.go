package monitoring

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rec := &statusRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		endpoint := r.URL.Path
		if route := mux.CurrentRoute(r); route != nil {
			if path, err := route.GetPathTemplate(); err == nil {
				endpoint = path
			}
		}

		HttpRequests.WithLabelValues(r.Method, endpoint).Inc()

		next.ServeHTTP(rec, r)

		duration := time.Since(start).Seconds()

		HttpResponses.WithLabelValues(
			r.Method,
			endpoint,
			strconv.Itoa(rec.statusCode),
		).Inc()

		HttpDuration.WithLabelValues(r.Method, endpoint).Observe(duration)
	})
}