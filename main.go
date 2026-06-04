package main

import (
	"net/http"
	"sync/atomic"
	"fmt"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc( next http.Handler) http.Handler {
    return http.HandlerFunc(
        func(w http.ResponseWriter, r *http.Request) {
            cfg.fileserverHits.Add(1)
            next.ServeHTTP(w, r)
        },
    )
}

func (cfg *apiConfig) writeMetric(w http.ResponseWriter, r *http.Request) {
	count := cfg.fileserverHits.Load()
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html>
			<body>
				<h1>Welcome, Chirpy Admin</h1>
				<p>Chirpy has been visited %d times!</p>
			</body>
			</html>`, count)
}

func (cfg *apiConfig) resetMetric(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	fmt.Fprintf(w, "Counter reset")
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "OK")
}

func main() {
	mux := http.NewServeMux()
	cfg := apiConfig{}
	fileServer := http.StripPrefix(
		"/app",
		http.FileServer(http.Dir(".")),
	)

	mux.Handle(
		"/app/",
		cfg.middlewareMetricsInc(fileServer),
	)

	mux.HandleFunc("GET /admin/metrics", cfg.writeMetric)
	mux.HandleFunc("POST /admin/reset", cfg.resetMetric)
	mux.HandleFunc("GET /api/healthz", healthCheck)

	server := &http.Server{
		Handler: mux,
		Addr: ":8080",
	}
	server.ListenAndServe()
}