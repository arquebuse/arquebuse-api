package users

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/arquebuse/arquebuse-api/pkg/common"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
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

// Sort users by Username
type ByUsername []PublicUser

func (a ByUsername) Len() int           { return len(a) }
func (a ByUsername) Less(i, j int) bool { return a[i].Username < a[j].Username }
func (a ByUsername) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

var config *configuration.Config
var users map[string]*PrivateUser

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
		router.Delete("/{username}", deleteOneUser)
		router.Patch("/{username}", updateOneUser)
		router.Post("/", addOneUser)
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

// Save users into user file
func saveUsers(userFile string) error {

	p := configuration.SearchFile(userFile)
	if p != "" {
		content, err := yaml.Marshal(&users)
		if err != nil {
			return err
		}

		fileInfo, err := os.Stat(userFile)
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(userFile, content, fileInfo.Mode())
		if err != nil {
			return err
		}

	} else {
		return errors.New("no user file '" + userFile + "' where found")
	}

	log.Printf("Successfully saved %d user(s) from '%s'\n", len(users), p)
	return nil
}

// Get all users
func Users() map[string]*PrivateUser {
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

// Update a user
func updateUser(username string, user PrivateUser) error {

	if _, ok := users[username]; ok {
		users[username] = &user
	} else {
		return errors.New("user '" + username + "' does't exist")
	}

	return saveUsers(config.Security.UserFile)
}

// Add a user
func addUser(username string, user PrivateUser) error {

	if username == "" {
		return errors.New("username cannot be empty")
	}

	if username == "me" {
		return errors.New("'me' is a reserved username")
	}

	if _, exists := users[username]; exists {
		return errors.New("user '" + username + "' already exists")
	} else {
		users[username] = &user
	}

	return saveUsers(config.Security.UserFile)
}

// Delete a user
func deleteUser(username string) error {

	if _, ok := users[username]; ok {
		delete(users, username)
	} else {
		return errors.New("user '" + username + "' does't exist")
	}

	return saveUsers(config.Security.UserFile)
}

// Get all users (API)
func allUsers(w http.ResponseWriter, r *http.Request) {

	var response []PublicUser

	for username := range users {
		user, _ := User(username)
		response = append(response, user)
	}

	sort.Sort(ByUsername(response))
	render.JSON(w, r, response)
}

// Get all users (API)
func oneUser(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	if username == "me" {
		_, claims, err := jwtauth.FromContext(r.Context())

		if err != nil {
			log.Printf("ERROR - Unable to get Claims from context. Error: %s\n", err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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

// Update a user (API)
func updateOneUser(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	userToUpdate := username

	type Request struct {
		Password    string   `json:"password"`
		NewPassword string   `json:"newPassword"`
		FullName    string   `json:"fullName"`
		Roles       []string `json:"roles"`
	}

	user := PrivateUser{}

	var request Request
	err := json.NewDecoder(r.Body).Decode(&request)

	if err != nil {
		log.Printf("ERROR - Failed to decode request. Error: %s\n", err.Error())
		http.Error(w, "Unable to decode request", http.StatusBadRequest)
		return
	}

	if username == "me" {
		_, claims, err := jwtauth.FromContext(r.Context())

		if err != nil {
			log.Printf("ERROR - Unable to get Claims from context. Error: %s\n", err.Error())
			http.Error(w, "Failed to update user", http.StatusInternalServerError)
		}

		userToUpdate = fmt.Sprintf("%v", claims["username"])
	}

	if request.NewPassword != "" {
		if len(request.NewPassword) < 6 {
			log.Printf("ERROR - Failed to update user '%s'. Password too short\n", userToUpdate)
			http.Error(w, "New password must contains at least 6 characters", http.StatusBadRequest)
			return
		}

		if username == "me" {
			passwordHash := users[userToUpdate].PasswordHash
			if common.CompareSecretAndHash(request.Password, passwordHash) != nil {
				log.Printf("ERROR - Failed to update user '%s'. Bad current password\n", userToUpdate)
				http.Error(w, "Bad current password", http.StatusBadRequest)
				return
			}
		}

		passwordHash, err := common.HashSecret(request.NewPassword)
		if err != nil {
			log.Printf("ERROR - Failed to hash provided password. Error: %s\n", err.Error())
			http.Error(w, "Failed to update user", http.StatusInternalServerError)
			return
		}

		user.PasswordHash = passwordHash
	} else {
		user.PasswordHash = users[userToUpdate].PasswordHash
	}

	if len(request.Roles) > 0 && username != "me" {
		// FIXME: check if role is valid
		user.Roles = request.Roles
	} else {
		user.Roles = users[userToUpdate].Roles
	}

	if request.FullName != "" {
		user.FullName = request.FullName
	} else {
		user.FullName = users[userToUpdate].FullName
	}

	user.ApiKeyHash = users[userToUpdate].ApiKeyHash

	err = updateUser(userToUpdate, user)

	if err == nil {
		log.Printf("Successfully updated user '%s'\n", userToUpdate)
		render.PlainText(w, r, "User successfully modified")
	} else {
		log.Printf("ERROR - Unable to update user '%s'. Error: %s\n", userToUpdate, err.Error())
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
	}
}

// Delete a user (API)
func deleteOneUser(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	if _, exists := users[username]; !exists {
		log.Printf("ERROR - user '%s' not found\n", username)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	_, claims, err := jwtauth.FromContext(r.Context())

	if err != nil {
		log.Printf("ERROR - Unable to get Claims from context. Error: %s\n", err.Error())
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	currentUsername := fmt.Sprintf("%v", claims["username"])

	if username != currentUsername {
		err = deleteUser(username)
		if err == nil {
			log.Printf("Successfully deleted user '%s'\n", username)
			render.PlainText(w, r, "User successfully deleted")
		} else {
			log.Printf("ERROR - Unable to delete user '%s'. Error: %s\n", username, err.Error())
			http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		}
	} else {
		log.Printf("ERROR - Unable to delete current user '%s'\n", username)
		http.Error(w, "Cannot delete current user", http.StatusBadRequest)
	}
}

// Add a new user (API)
func addOneUser(w http.ResponseWriter, r *http.Request) {

	type Request struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		FullName string   `json:"fullName"`
		Roles    []string `json:"roles"`
	}

	var request Request
	err := json.NewDecoder(r.Body).Decode(&request)

	if err != nil {
		log.Printf("ERROR - Failed to decode request. Error: %s\n", err.Error())
		http.Error(w, "Unable to decode request", http.StatusBadRequest)
		return
	}

	user := PrivateUser{
		FullName: request.FullName,
	}

	// FIXME: check if roles are valid
	user.Roles = request.Roles

	passwordHash, err := common.HashSecret(request.Password)
	if err != nil {
		log.Printf("ERROR - Failed to hash provided password. Error: %s\n", err.Error())
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	user.PasswordHash = passwordHash

	err = addUser(request.Username, user)

	if err == nil {
		log.Printf("Successfully created user '%s'\n", request.Username)
		render.PlainText(w, r, "User successfully created")
	} else {
		log.Printf("ERROR - Failed to create user. Error: %s\n", err.Error())
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
	}
}
