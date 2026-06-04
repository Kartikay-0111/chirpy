package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"io"
	"strings"
	"os"
	"database/sql"
	"github.com/joho/godotenv"
	"github.com/Kartikay-0111/chirpy/internal/database"
	"github.com/google/uuid"
	"time"
)

import _ "github.com/lib/pq"

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries *database.Queries
	Platform string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
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
	cfg.dbQueries.DeleteAllUsers(r.Context())
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "OK")
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) error {
	response, err := json.Marshal(payload)

	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(code)
	w.Write(response)

	return nil
}

func respondWithError(w http.ResponseWriter, code int, msg string) error {
    return respondWithJSON(w, code, map[string]string{"error": msg})
}


func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	
	type requestBody struct {
		Email string `json:"email"`
	}

	type responseBody struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}

	dat, err := io.ReadAll(r.Body)
    if err != nil {
        respondWithError(w, 500, "couldn't read request")
        return
    }
    params := requestBody{}
    err = json.Unmarshal(dat, &params)
    if err != nil {
        respondWithError(w, 500, "couldn't unmarshal parameters")
        return
    }
	user, err := cfg.dbQueries.CreateUser(r.Context(), params.Email)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		respondWithError(w, 500, "couldn't create user")
		return
	}
	respondWithJSON(w, 201, responseBody{
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
	})
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	
	type requestBody struct {
		Body string `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}
	
	type responseBody struct {
		Id uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body string `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}
	dat, err := io.ReadAll(r.Body)
    if err != nil {
        respondWithError(w, 500, "couldn't read request")
        return
    }
    params := requestBody{}
    err = json.Unmarshal(dat, &params)
    if err != nil {
        respondWithError(w, 500, "couldn't unmarshal parameters")
        return
    }

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	} 
	cleanedBody := params.Body
	words := strings.Split(cleanedBody, " ")
	for i, word := range words {
		if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
			words[i] = "****"
		}
	}
	cleanedBody = strings.Join(words, " ")
	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
		Body: cleanedBody,
		UserID: params.UserID,
	})
	if err != nil {
		log.Printf("Error creating chirp: %v", err)
		respondWithError(w, 500, "couldn't create chirp")
		return
	}
	respondWithJSON(w, 201, responseBody{
		Id: chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body: chirp.Body,
		UserID: chirp.UserID,
	})
}

func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.dbQueries.GetAllChirps(r.Context())
	if err != nil {
		log.Printf("Error getting chirps: %v", err)
		respondWithError(w, 500, "couldn't get chirps")
		return
	}
	type responseBody struct {
		ID uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body string `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}
	resp := make([]responseBody, len(chirps))
	for i, chirp := range chirps {
		resp[i] = responseBody{
			ID: chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body: chirp.Body,
			UserID: chirp.UserID,
		}
	}
	respondWithJSON(w, 200, resp)
}

func (cfg *apiConfig) getChirpById(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("chirpId")
	id, err := uuid.Parse(idStr)
	if err != nil {
		log.Printf("Error parsing UUID: %v", err)
		respondWithError(w, 400, "invalid chirp ID")
		return
	}
	chirp, err := cfg.dbQueries.GetChirpById(r.Context(), id)
	if err != nil {
		log.Printf("Error getting chirp by ID: %v", err)
		respondWithError(w, 404, "couldn't get chirp")
		return
	}
	type responseBody struct {
		ID uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body string `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}
	respondWithJSON(w, 200, responseBody{
		ID: chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body: chirp.Body,
		UserID: chirp.UserID,
	})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Error connecting to database")
	}
	defer db.Close()

	dbQueries := database.New(db)
	cfg := apiConfig{dbQueries: dbQueries}

	mux := http.NewServeMux()
	fileServer := http.StripPrefix(
		"/app",
		http.FileServer(http.Dir(".")),
	)

	mux.Handle(
		"/app/",
		cfg.middlewareMetricsInc(fileServer),
	)

	mux.HandleFunc("GET /api/healthz", healthCheck)
	mux.HandleFunc("GET /admin/metrics", cfg.writeMetric)
	mux.HandleFunc("POST /admin/reset", cfg.resetMetric)
	mux.HandleFunc("POST /api/chirps", cfg.createChirp)
	mux.HandleFunc("POST /api/users", cfg.createUser)
	mux.HandleFunc("GET /api/chirps", cfg.getChirps)
	mux.HandleFunc("GET /api/chirps/{chirpId}", cfg.getChirpById)

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	server.ListenAndServe()
}

