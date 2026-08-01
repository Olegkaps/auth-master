package httptransport

// swaggerDocHealthz documents the liveness route wired in server.go.
// @Summary Liveness probe
// @Description Returns 204 when the process accepts HTTP.
// @Tags system
// @Success 204 "No content"
// @Router /healthz [get]
func swaggerDocHealthz() {}

// swaggerDocMetrics documents the Prometheus metrics route in server.go.
// @Summary Prometheus metrics
// @Description OpenMetrics/Prometheus text exposition format.
// @Tags system
// @Produce plain
// @Success 200 {string} string "Metrics body"
// @Router /metrics [get]
func swaggerDocMetrics() {}
