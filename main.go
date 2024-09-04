package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

const JWT_SIGNING_KEY = "this-is-my-secret-key"

func GenerateJwtToken(username string)(string, error){
	now := time.Now()
	expires := now.Add(time.Second * 15).Unix()
	claims := jwt.MapClaims{
		"sub": username,
		"expire": expires,
	}
	// generate token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// sign token
	return token.SignedString([]byte(JWT_SIGNING_KEY))
}

func ValidateToken(tokenStr string)(jwt.MapClaims, error){
	// parse
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC);!ok {
			return nil, fmt.Errorf("invalid token")
		}
		return[]byte(JWT_SIGNING_KEY), nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}

	// check token validity
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	

	// get claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token")
	}

	// check expire claims
	expireValue := claims["expire"]
	expires := int64(expireValue)
	fmt.Println(expireValue)
	return claims, nil
}

func LoginHandler (w http.ResponseWriter, r *http.Request) {
	var loginParams LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginParams)
	if err != nil {
		http.Error(w, "invalid credencials", http.StatusBadRequest)
		return
	}
	if loginParams.Username == "gerson" && loginParams.Password == "123456" {
		token, err := GenerateJwtToken("gerson")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res := LoginResponse{
			Token: token,
		}

		err = json.NewEncoder(w).Encode(&res)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}
	http.Error(w, "invalid credencials", http.StatusBadRequest)
}

func SecureHandler (w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("you are authenticated"))
}

func PublicHandler (w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("everyone can view this endpoint"))
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Api-Token")
		if len(token) == 0 {
			http.Error(w, "not authorized", http.StatusUnauthorized)
			return
		}
		// validate token
		claims, err := ValidateToken(token)
		if err != nil {
			http.Error(w, "not authorized", http.StatusUnauthorized)
			return
		}
		fmt.Println(claims)
		next.ServeHTTP(w, r)
	}
}

func main() {
	http.HandleFunc("/api/auth", LoginHandler)
	http.HandleFunc("/api/public", PublicHandler)
	http.HandleFunc("/api/secure", AuthMiddleware(SecureHandler))
	http.ListenAndServe(":8000", nil)
}