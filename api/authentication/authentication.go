package authentication

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/arquebuse/arquebuse-api/pkg/common"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"
	"log"
	"net/http"
	"strings"
	"time"
)

// JWT Claim struct
type Claims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.StandardClaims
}

// Failed authentication attempts struct
type Failed struct {
	lastAttempt time.Time
	failCount   int
}

var config *configuration.Config
var failAuth map[string]*Failed

func Routes(configuration *configuration.Config) *chi.Mux {
	config = configuration
	router := chi.NewRouter()

	failAuth = map[string]*Failed{}

	// JWT protected endpoints
	router.Group(func(router chi.Router) {
		router.Use(jwtauth.Verifier(config.Security.JWTAuth))
		router.Use(jwtauth.Authenticator)
		router.Get("/renew", renew)
		router.Get("/check", check)
	})

	// Unprotected endpoints
	router.Group(func(router chi.Router) {
		router.Post("/login", authenticateUAP)
		router.Post("/hash", hash)
	})

	return router
}

// Lookup client IP Address in failed authentication dict and apply a delay if needed
func checkFailed(clientIPAddress string) {
	if failureEntry, ok := failAuth[clientIPAddress]; ok {
		fiveMinutesAgo := time.Now().Add(time.Duration(-1) * time.Minute)
		if fiveMinutesAgo.Before(failureEntry.lastAttempt) {
			time.Sleep(time.Duration(failureEntry.failCount) * time.Second)
		} else {
			delete(failAuth, clientIPAddress)
		}
	}
}

// Record a failed auth attempt
func recordFailed(clientIPAddress string) {
	if _, ok := failAuth[clientIPAddress]; ok {
		failAuth[clientIPAddress].failCount++
		failAuth[clientIPAddress].lastAttempt = time.Now()
	} else {
		failAuth[clientIPAddress] = &Failed{
			failCount:   1,
			lastAttempt: time.Now(),
		}
	}
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

	user, err := configuration.User(username)

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
func authenticateUAP(w http.ResponseWriter, r *http.Request) {

	type Request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// if client IP previously failed, wait a few seconds
	checkFailed(r.RemoteAddr)

	var request Request
	err := json.NewDecoder(r.Body).Decode(&request)
	userList := configuration.Users()

	if err != nil {
		http.Error(w, "Unable to decode request", http.StatusBadRequest)
		return
	}

	username := strings.ToLower(request.Username)

	if user, exists := userList[username]; exists {
		err = common.CompareSecretAndHash(request.Password, user.PasswordHash)

		if err == nil {
			response := make(map[string]string)
			response["bearerToken"], err = issueToken(username)
			if err != nil {
				log.Fatalf("ERROR - Unable to generate a JWT token for user '%s'. Error: %s\n", username, err.Error())
			}

			user, err := configuration.User(username)
			if err != nil {
				log.Fatalf("ERROR - Unable to get user details for user '%s'. Error: %s\n", username, err.Error())
			}
			response["fullName"] = user.FullName
			response["username"] = username

			log.Printf("Successfully authentified user '%s' with Password\n", username)
			render.JSON(w, r, response)
			return
		} else {
			log.Printf("WARN - Wrong password user '%s'\n", username)
		}
	} else {
		log.Printf("WARN - Unknown user '%s'\n", username)
	}

	recordFailed(r.RemoteAddr)
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// Renew a user token
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

	user, err := configuration.User(username)
	if err != nil {
		log.Fatalf("ERROR - Unable to get user details for user '%s'. Error: %s\n", username, err.Error())
	}
	response["fullName"] = user.FullName
	response["username"] = username

	render.JSON(w, r, response)
}

// Just return 200 if authenticated
func check(w http.ResponseWriter, r *http.Request) {

	render.PlainText(w, r, "")
}

// Function to check for API key in headers or a valid JWT token and add user info into context
func Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		apiKey := r.Header.Get("X-API-Key")
		userList := configuration.Users()
		username := ""
		var roles []string

		if apiKey != "" {
			// API Key
			for login, userDetails := range userList {
				if userDetails.ApiKeyHash != "" {
					err := common.CompareSecretAndHash(apiKey, userDetails.ApiKeyHash)

					if err == nil {
						username = login
						roles = userDetails.Roles
					}
				}
			}
		} else {
			// JWT Token
			token, claims, err := jwtauth.FromContext(r.Context())

			if err == nil && token != nil && token.Valid {
				username = fmt.Sprintf("%v", claims["username"])
				roles = userList[username].Roles
			}
		}

		// User is authenticated, enrich context
		if username != "" {
			ctx := context.WithValue(r.Context(), "username", username)
			ctx = context.WithValue(ctx, "roles", roles)

			// Continue request processing
			next.ServeHTTP(w, r.WithContext(ctx))

		} else {
			// Reject request as unauthorized
			http.Error(w, http.StatusText(401), 401)
			return
		}
	})
}
