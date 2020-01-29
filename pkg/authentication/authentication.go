package authentication

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/arquebuse/arquebuse-api/pkg/common"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/arquebuse/arquebuse-api/pkg/users"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"
	"log"
	"net/http"
	"time"
)

type Claims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.StandardClaims
}

var config *configuration.Config

func Routes(configuration *configuration.Config) *chi.Mux {
	config = configuration
	router := chi.NewRouter()

	// JWT protected endpoints
	router.Group(func(router chi.Router) {
		router.Use(jwtauth.Verifier(config.Security.JWTAuth))
		router.Use(jwtauth.Authenticator)
		router.Get("/renew", renew)
		router.Get("/check", check)
	})

	// Unprotected endpoints
	router.Group(func(router chi.Router) {
		router.Post("/login", authenticate)
		router.Post("/hash", hash)
	})

	return router
}

// Initialize JWT auth objects (is called before Routes() so config variable is not initialized yet)
func InitializeJWT(configuration *configuration.Config) {
	c := 32
	jwtKey := make([]byte, c)
	_, err := rand.Read(jwtKey)
	if err != nil {
		log.Fatalf("ERROR - Unable to generate a new JWT key. Error: %s\n", err.Error())
	}

	configuration.Security.JWTAuth = jwtauth.New("HS256", jwtKey, nil)
}

// Issues a JWT token for a user
func issueToken(username string) (string, error) {

	user, err := users.User(username)

	if err != nil {
		return "", err
	}

	// set expiration in 15 minutes
	expirationTime := time.Now().Add(15 * time.Minute)

	claims := &Claims{
		Username: username,
		Roles:    user.Roles,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	_, tokenString, err := config.Security.JWTAuth.Encode(claims)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Returns the hash of provided secret
func hash(w http.ResponseWriter, r *http.Request) {
	type Request struct {
		Secret string `json:"secret"`
	}

	var request Request
	err := json.NewDecoder(r.Body).Decode(&request)

	if err != nil {
		http.Error(w, "Unable to decode request", http.StatusBadRequest)
		return
	}

	response := make(map[string]string)
	response["hash"], err = common.HashSecret(request.Secret)

	if err != nil {
		log.Fatalf("ERROR - Unable to hash provided secret. Error: %s\n", err.Error())
	}

	render.JSON(w, r, response)
}

// Get authenticate a user based on a user/password
func authenticate(w http.ResponseWriter, r *http.Request) {

	type Request struct {
		Username string `json:"username"`
		Password string `json:"password"`
		ApiKey   string `json:"api-key"`
	}

	var request Request
	err := json.NewDecoder(r.Body).Decode(&request)
	userList := users.Users()

	if err != nil {
		http.Error(w, "Unable to decode request", http.StatusBadRequest)
		return
	}

	// Authentication with User and Password
	if request.Username != "" {
		username := request.Username

		if user, exists := userList[username]; exists {
			err = common.CompareSecretAndHash(request.Password, user.PasswordHash)

			if err == nil {
				response := make(map[string]string)
				response["bearerToken"], err = issueToken(username)
				if err != nil {
					log.Fatalf("ERROR - Unable to generate a JWT token for user '%s'. Error: %s\n", username, err.Error())
				}

				user, err := users.User(username)
				if err != nil {
					log.Fatalf("ERROR - Unable to get user details for user '%s'. Error: %s\n", username, err.Error())
				}
				response["fullName"] = user.FullName

				log.Printf("Successfully authentified user '%s' with Password\n", username)
				render.JSON(w, r, response)
				return
			} else {
				log.Printf("WARN - Wrong password user '%s'\n", username)
			}
		} else {
			log.Printf("WARN - Unknown user '%s'\n", username)
		}
	}

	// Authentication with API Key
	if request.ApiKey != "" {
		apiKey := request.ApiKey

		for username, userDetails := range userList {
			if userDetails.ApiKeyHash != "" {
				err = common.CompareSecretAndHash(apiKey, userDetails.ApiKeyHash)

				if err == nil {
					response := make(map[string]string)
					response["bearerToken"], err = issueToken(username)
					if err != nil {
						log.Fatalf("ERROR - Unable to generate a JWT token for user '%s'. Error: %s\n", username, err.Error())
					}

					user, err := users.User(username)
					if err != nil {
						log.Fatalf("ERROR - Unable to get user details for user '%s'. Error: %s\n", username, err.Error())
					}
					response["fullName"] = user.FullName

					log.Printf("Successfully authentified user '%s' with API Key\n", username)
					render.JSON(w, r, response)
					return
				}
			}
		}

		log.Printf("WARN - No user matched API Key: '%s'\n", apiKey)
	}

	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// Get authenticate a user based on a user/password
func renew(w http.ResponseWriter, r *http.Request) {

	_, claims, err := jwtauth.FromContext(r.Context())

	if err != nil {
		log.Fatalf("ERROR - Unable to get Claims from context. Error: %s\n", err.Error())
	}

	username := fmt.Sprintf("%v", claims["username"])

	response := make(map[string]string)
	response["bearerToken"], err = issueToken(username)
	if err != nil {
		log.Fatalf("ERROR - Unable to generate a JWT token for user '%s'. Error: %s\n", username, err.Error())
	}

	user, err := users.User(username)
	if err != nil {
		log.Fatalf("ERROR - Unable to get user details for user '%s'. Error: %s\n", username, err.Error())
	}
	response["fullName"] = user.FullName

	render.JSON(w, r, response)
}

// Just return 200 if authenticated
func check(w http.ResponseWriter, r *http.Request) {

	render.PlainText(w, r, "")
}
