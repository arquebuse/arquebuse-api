package users

import (
	"errors"
	"fmt"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
)

// User for internal usage
type PrivateUser struct {
	FullName     string   `yaml:"fullName"`
	PasswordHash string   `yaml:"passwordHash"`
	ApiKeyHash   string   `yaml:"apiKeyHash"`
	Roles        []string `yaml:"roles"`
}

// User for API outputs
type PublicUser struct {
	Username        string   `json:"username"`
	FullName        string   `json:"fullName"`
	Roles           []string `json:"roles"`
	Authentications []string `json:"authentications"`
}

var config *configuration.Config
var users map[string]PrivateUser

func Routes(configuration *configuration.Config) *chi.Mux {
	config = configuration

	// Load users
	loadUsers(config.Security.UserFile)

	router := chi.NewRouter()

	// JWT protected endpoints
	router.Group(func(router chi.Router) {
		router.Use(jwtauth.Verifier(config.Security.JWTAuth))
		router.Use(jwtauth.Authenticator)
		router.Get("/", allUsers)
		router.Get("/{username}", oneUser)
	})

	return router
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

// Get all users
func Users() map[string]PrivateUser {
	return users
}

// Get a user
func User(username string) (PublicUser, error) {
	var authentications []string

	if user, ok := users[username]; ok {
		if user.ApiKeyHash != "" {
			authentications = append(authentications, "API-Key")
		}

		if user.PasswordHash != "" {
			authentications = append(authentications, "Password")
		}

		return PublicUser{
			Username:        username,
			FullName:        user.FullName,
			Roles:           user.Roles,
			Authentications: authentications,
		}, nil
	} else {
		return PublicUser{}, errors.New("user not found")
	}
}

// Get all users (API)
func allUsers(w http.ResponseWriter, r *http.Request) {

	var response []PublicUser

	for username := range users {
		user, _ := User(username)
		response = append(response, user)
	}

	render.JSON(w, r, response)
}

// Get all users (API)
func oneUser(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	if username == "me" {
		_, claims, err := jwtauth.FromContext(r.Context())

		if err != nil {
			log.Fatalf("ERROR - Unable to get Claims from context. Error: %s\n", err.Error())
		}

		username = fmt.Sprintf("%v", claims["username"])
	}

	user, err := User(username)

	if err == nil {
		render.JSON(w, r, user)
	} else {
		http.Error(w, "User not found", http.StatusNotFound)
	}
}
