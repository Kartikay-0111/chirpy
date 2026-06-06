package auth

import (
    "github.com/alexedwards/argon2id"
    "time"
    "github.com/google/uuid"
    "github.com/golang-jwt/jwt/v5"
    "fmt"
    "strings"
    "net/http"
    "crypto/rand"
    "encoding/hex"
)

func HashPassword(password string) (string, error) {
    return argon2id.CreateHash(password, argon2id.DefaultParams)
}

func CheckPasswordHash(password, hash string) (bool, error) {
    return argon2id.ComparePasswordAndHash(password, hash)
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error){
    now := time.Now()
    claims := jwt.RegisteredClaims{
        Subject:   userID.String(),
        IssuedAt:  jwt.NewNumericDate(now),
        ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
        Issuer: "chirpy-access",
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

    tokenString, err := token.SignedString([]byte(tokenSecret))
    if err != nil {
        return "", err
    }
    return tokenString, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
    claims := &jwt.RegisteredClaims{}

    token, err := jwt.ParseWithClaims(
        tokenString,
        claims,
        func(token *jwt.Token) (interface{}, error) {
            return []byte(tokenSecret), nil
        },
    )
    if err != nil {
        return uuid.Nil, err
    }

    if !token.Valid {
        return uuid.Nil, fmt.Errorf("invalid token")
    }

    userID, err := uuid.Parse(claims.Subject)
    if err != nil {
        return uuid.Nil, err
    }

    return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
    authHeader := headers.Get("Authorization")
    if authHeader == "" {
        return "", fmt.Errorf("authorization header missing")
    }
    
    parts := strings.SplitN(authHeader, " ", 2)
    if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
        return "", fmt.Errorf("invalid authorization header format")
    }
    
    return parts[1], nil
}

func MakeRefreshToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    encodedStr := hex.EncodeToString(b)
    return encodedStr
}


// extract the api key from the Authorization header, which is expected to be in this format:
// Authorization: ApiKey THE_KEY_HERE
// need to strip out the ApiKey part and the whitespace and return just the key.
func GetAPIKey(headers http.Header) (string, error) {
    header := headers.Get("Authorization")
    if header == "" {
        return "", fmt.Errorf("API key missing")
    }
    parts := strings.SplitN(header, " ", 3)
    if len(parts) != 3 || strings.ToLower(parts[0]) != "apikey" {
        return "", fmt.Errorf("invalid API key format")
    }
    return parts[2], nil
}