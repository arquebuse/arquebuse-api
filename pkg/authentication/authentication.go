package authentication

import (
	"crypto/rand"
	"encoding/json"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type User struct {
	FullName     string   `yaml:"fullName"`
	PasswordHash string   `yaml:"passwordHash"`
	Roles        []string `yaml:"roles"`
}

type Claims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.StandardClaims
}

var config *configuration.Config
var users map[string]User

// var jwtKey []byte

func Routes(configuration *configuration.Config) *chi.Mux {
	config = configuration

	// Load users
	loadUsers(config.Security.UserFile)

	router := chi.NewRouter()
	router.Post("/tokens", authenticateUAP)
	router.Post("/passwords", hashPassword)
	return router
}

// Get authenticate a user based on a user/password
func authenticateUAP(w http.ResponseWriter, r *http.Request) {

	type Request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var request Request
	err := json.NewDecoder(r.Body).Decode(&request)

	if err != nil {
		http.Error(w, "Unable to decode request", http.StatusBadRequest)
		return
	}

	username := request.Username

	if user, exists := users[username]; exists {
		err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password))

		if err == nil {
			response := make(map[string]string)
			response["bearerToken"], err = issueToken(username)
			if err != nil {
				log.Fatalf("ERROR - Unable to generate a JWT token for user '%s'. Error: %s\n", username, err.Error())
			}

			log.Printf("Successfully authentified user '%s'\n", username)
			render.JSON(w, r, response)
			return
		} else {
			log.Printf("WARN - Wrong password user '%s'\n", username)
		}
	} else {
		log.Printf("WARN - Unknown user '%s'\n", username)
	}

	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// Returns the hash of provided password
func hashPassword(w http.ResponseWriter, r *http.Request) {
	type Request struct {
		Password string `json:"password"`
	}

	var request Request
	err := json.NewDecoder(r.Body).Decode(&request)

	if err != nil {
		http.Error(w, "Unable to decode request", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}

	response := make(map[string]string)
	response["passwordHash"] = string(hash)

	render.JSON(w, r, response)
}

// Load users from user file
func loadUsers(userFile string) {

	p := configuration.SearchFile(userFile)
	if p != "" {
		c, err := ioutil.ReadFile(p)
		if err != nil {
			log.Fatalf("ERROR - Unable to read user file '%s'. Error: %s\n", p, err.Error())
		} else {
			err := yaml.Unmarshal(c, &users)
			if err != nil {
				log.Fatalf("ERROR - Failed to parse user file '%s'. Error: %s\n", p, err.Error())
			}
		}
	} else {
		log.Fatalf("ERROR - No user file '%s' where found\n", userFile)
	}

	log.Printf("Successfully loaded %d user(s) from '%s'\n", len(users), p)
}

// Issues a JWT token for a user
func issueToken(username string) (string, error) {

	// set expiration in 15 minutes
	expirationTime := time.Now().Add(15 * time.Minute)

	claims := &Claims{
		Username: username,
		Roles:    users[username].Roles,
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
