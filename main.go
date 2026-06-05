package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/Kartikay-0111/chirpy/internal/auth"
	"github.com/Kartikay-0111/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

import _ "github.com/lib/pq"

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	Platform       string
	SecretKey      string
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
		Password string `json:"password"`
		Email    string `json:"email"`
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
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		respondWithError(w, 500, "couldn't hash password")
		return
	}
	user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		log.Printf("Error creating user: %v", err)
		respondWithError(w, 500, "couldn't create user")
		return
	}
	respondWithJSON(w, 201, responseBody{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	})
}

func (cfg *apiConfig) loginUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	type requestBody struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	type responseBody struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
		Token     string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
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
	user, err := cfg.dbQueries.GetUser(r.Context(), params.Email)
	if err != nil {
		respondWithError(w, 404, "user not found")
		return
	}

	isValid, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, 500, "couldn't check password")
		return
	}
	if !isValid {
		respondWithError(w, 401, "Incorrect email or password")
		return
	}

	expiresIn := time.Hour
	token, err := auth.MakeJWT(user.ID, cfg.SecretKey, expiresIn)

	if err != nil {	
		respondWithError(w, 500, "couldn't make JWT")
		return
	}
	
	refresh_token := auth.MakeRefreshToken()
	_, err = cfg.dbQueries.InsertRefreshToken(r.Context(), database.InsertRefreshTokenParams{
		Token: refresh_token,
		UserID: user.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
	})
	if err != nil {
		log.Printf("Error inserting refresh token: %v", err)
		respondWithError(w, 500, "couldn't create refresh token")
		return
	}
	respondWithJSON(w, 200, responseBody{
		Id:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
		Token:     token,
		RefreshToken: refresh_token,
	})
}

func (cfg *apiConfig) updateUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	
	type requestBody struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	token := r.Header.Get("Authorization")
	if token == "" {
		respondWithError(w, 401, "missing token")
		return
	}
	token = strings.TrimPrefix(token, "Bearer ")
	userID, err := auth.ValidateJWT(token, cfg.SecretKey)
	if err != nil {
		respondWithError(w, 401, "invalid token")
		return
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
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		respondWithError(w, 500, "couldn't hash password")
		return
	}
	user, err := cfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
		Email: sql.NullString{
			String: params.Email,
			Valid:  true,
		},
		ID: userID,
		HashedPassword: sql.NullString{
			String: hashedPassword,
			Valid:  true,
		},
	})
	if err != nil {
		log.Printf("Error updating user: %v", err)
		respondWithError(w, 500, "couldn't update user")
		return
	}
	type responseBody struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}
	respondWithJSON(w, 200, responseBody{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	})
}

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "missing refresh token")
		return
	}

	tokenRecord, err := cfg.dbQueries.GetUserFromRefreshToken(
		r.Context(),
		refreshToken,
	)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	if tokenRecord.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "token revoked")
		return
	}

	if tokenRecord.ExpiresAt.Before(time.Now()) {
		respondWithError(w, http.StatusUnauthorized, "token expired")
		return
	}

	accessToken, err := auth.MakeJWT(
		tokenRecord.UserID,
		cfg.SecretKey,
		time.Hour,
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "couldn't create jwt")
		return
	}

	type response struct {
		Token string `json:"token"`
	}

	respondWithJSON(w, http.StatusOK, response{
		Token: accessToken,
	})
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "missing refresh token")
		return
	}

	err = cfg.dbQueries.RevokeRefreshToken(
		r.Context(),
		refreshToken,
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "couldn't revoke token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	type requestBody struct {
		Body   string    `json:"body"`
	}

	type responseBody struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
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
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "missing or invalid token")
		return
	}
	id, err := auth.ValidateJWT(token, cfg.SecretKey)
	if err != nil {
		respondWithError(w, 401, "invalid token")
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
		Body:   cleanedBody,
		UserID: id,
	})
	if err != nil {
		log.Printf("Error creating chirp: %v", err)
		respondWithError(w, 500, "couldn't create chirp")
		return
	}
	respondWithJSON(w, 201, responseBody{
		Id:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
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
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}
	resp := make([]responseBody, len(chirps))
	for i, chirp := range chirps {
		resp[i] = responseBody{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
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
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}
	respondWithJSON(w, 200, responseBody{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	})
}

func (cfg *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("chirpId")
	id, err := uuid.Parse(idStr)
	chirp, err := cfg.dbQueries.GetChirpById(r.Context(), id)
	if err != nil {
		log.Printf("Error getting chirp by ID: %v", err)
		respondWithError(w, 404, "couldn't get chirp")
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "missing or invalid token")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.SecretKey)
	if err != nil {
		respondWithError(w, 401, "invalid token")
		return
	}
	if chirp.UserID != userID {
		respondWithError(w, 403, "forbidden: cannot delete others' chirps")
		return
	}
	if err != nil {
		log.Printf("Error parsing UUID: %v", err)
		respondWithError(w, 400, "invalid chirp ID")
		return
	}
	err = cfg.dbQueries.DeleteChirp(r.Context(), id)
	if err != nil {
		log.Printf("Error deleting chirp: %v", err)
		respondWithError(w, 500, "couldn't delete chirp")
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		log.Fatal("SECRET_KEY not set in environment")
	}
	cfg.SecretKey = secretKey

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
	mux.HandleFunc("POST /api/login", cfg.loginUser)
	mux.HandleFunc("POST /api/refresh", cfg.handlerRefresh)
	mux.HandleFunc("POST /api/revoke", cfg.handlerRevoke)
	mux.HandleFunc("PUT /api/users", cfg.updateUser)
	mux.HandleFunc("DELETE /api/chirps/{chirpId}", cfg.deleteChirp)

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	server.ListenAndServe()
}
