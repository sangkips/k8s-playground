package httpapi

import (
	"net/http"
	"time"

	"sangkips/k8s-playground/internal/http/handlers"
)

func NewServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handlers.Healthz)

	return &http.Server{
		Addr:              addr,
		Handler:          mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

