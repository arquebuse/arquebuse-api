package users

import (
	"encoding/json"
	"github.com/arquebuse/arquebuse-api/api/authentication"
	"github.com/arquebuse/arquebuse-api/pkg/common"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"
	"github.com/satori/go.uuid"
	"log"
	"net/http"
	"sort"
	"strings"
)

// User for API outputs
type PublicUser struct {
	Username       string   `json:"username"`
	FullName       string   `json:"fullName"`
	Authentication string   `json:"authentication"`
	Roles          []string `json:"roles"`
}

// Sort users by Username
type ByUsername []PublicUser

func (a ByUsername) Len() int           { return len(a) }
func (a ByUsername) Less(i, j int) bool { return a[i].Username < a[j].Username }
func (a ByUsername) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func Routes(config *configuration.Config) *chi.Mux {

	// Load users
	configuration.LoadUsers(config.Security.UserFile)

	router := chi.NewRouter()

	// JWT protected endpoints
	router.Group(func(router chi.Router) {
		router.Use(jwtauth.Verifier(config.Security.JWTAuth))
		router.Use(authentication.Authenticate)
		router.Get("/", allUsers)
		router.Get("/{username}", oneUser)
		router.Delete("/{username}", deleteOneUser)
		router.Patch("/{username}", updateOneUser)
		router.Post("/", addOneUser)
		router.Post("/{username}/api-key", addAPIKey)
	})

	return router
}

// Convert a Private user into a Public User
func toPublicUser(username string, userDetails configuration.PrivateUser) PublicUser {
	user := PublicUser{
		Username:       username,
		FullName:       userDetails.FullName,
		Roles:          userDetails.Roles,
		Authentication: "",
	}

	if userDetails.PasswordHash != "" {
		user.Authentication = "Password"
	} else {
		user.Authentication = "API-Key"
	}

	return user
}

// Get all users (API)
func allUsers(w http.ResponseWriter, r *http.Request) {

	var response []PublicUser
	users := configuration.Users()

	for username := range users {
		user := toPublicUser(username, *users[username])
		response = append(response, user)
	}

	sort.Sort(ByUsername(response))
	render.JSON(w, r, response)
}

// Get one user (API)
func oneUser(w http.ResponseWriter, r *http.Request) {
	username := strings.ToLower(chi.URLParam(r, "username"))

	if username == "me" {
		ctx := r.Context()
		username = ctx.Value("username").(string)
	}

	user, err := configuration.User(username)

	if err == nil {
		render.JSON(w, r, toPublicUser(username, user))
	} else {
		http.Error(w, "User not found", http.StatusNotFound)
	}
}

// Update a user (API)
func updateOneUser(w http.ResponseWriter, r *http.Request) {
	username := strings.ToLower(chi.URLParam(r, "username"))
	user := configuration.PrivateUser{}

	type Request struct {
		Password    string   `json:"password"`
		NewPassword string   `json:"newPassword"`
		FullName    string   `json:"fullName"`
		Roles       []string `json:"roles"`
	}

	var request Request
	err := json.NewDecoder(r.Body).Decode(&request)

	if err != nil {
		log.Printf("ERROR - Failed to decode request. Error: %s\n", err.Error())
		http.Error(w, "Unable to decode request", http.StatusBadRequest)
		return
	}

	if username == "me" {
		ctx := r.Context()
		username = ctx.Value("username").(string)
	}

	userToUpdate, err := configuration.User(username)
	if err != nil {
		log.Printf("ERROR - user '%s' not found\n", username)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if request.NewPassword != "" {
		if len(request.NewPassword) < 6 {
			log.Printf("ERROR - Failed to update user '%s'. Password too short\n", userToUpdate)
			http.Error(w, "New password must contains at least 6 characters", http.StatusBadRequest)
			return
		}

		if username == "me" {
			passwordHash := userToUpdate.PasswordHash
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
		user.ApiKeyHash = ""
	} else {
		user.PasswordHash = userToUpdate.PasswordHash
		user.ApiKeyHash = userToUpdate.ApiKeyHash
	}

	if len(request.Roles) > 0 && username != "me" {
		// FIXME: check if role is valid
		user.Roles = request.Roles
	} else {
		user.Roles = userToUpdate.Roles
	}

	if request.FullName != "" {
		user.FullName = request.FullName
	} else {
		user.FullName = userToUpdate.FullName
	}

	err = configuration.UpdateUser(username, user)

	if err == nil {
		log.Printf("Successfully updated user '%s'\n", username)
		render.PlainText(w, r, "User successfully modified")
	} else {
		log.Printf("ERROR - Unable to update user '%s'. Error: %s\n", userToUpdate, err.Error())
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
	}
}

// Delete a user (API)
func deleteOneUser(w http.ResponseWriter, r *http.Request) {
	username := strings.ToLower(chi.URLParam(r, "username"))

	_, err := configuration.User(username)

	if err != nil {
		log.Printf("ERROR - user '%s' not found\n", username)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	ctx := r.Context()
	currentUsername := ctx.Value("username").(string)

	if username != currentUsername {
		err = configuration.DeleteUser(username)
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

	user := configuration.PrivateUser{
		FullName: request.FullName,
	}

	// FIXME: check if roles are valid
	user.Roles = request.Roles

	passwordHash := ""
	if request.Password != "" {
		passwordHash, err = common.HashSecret(request.Password)
		if err != nil {
			log.Printf("ERROR - Failed to hash provided password. Error: %s\n", err.Error())
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}
	}

	user.PasswordHash = passwordHash
	username := strings.ToLower(request.Username)

	err = configuration.AddUser(username, user)

	if err == nil {
		log.Printf("Successfully created user '%s'\n", username)
		render.PlainText(w, r, "User successfully created")
	} else {
		log.Printf("ERROR - Failed to create user. Error: %s\n", err.Error())
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
	}
}

// Add an API-Key to a user (API)
func addAPIKey(w http.ResponseWriter, r *http.Request) {
	username := strings.ToLower(chi.URLParam(r, "username"))
	user := configuration.PrivateUser{}

	if username == "me" {
		ctx := r.Context()
		username = ctx.Value("username").(string)
	}

	user, err := configuration.User(username)
	if err != nil {
		log.Printf("ERROR - user '%s' not found\n", username)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	uuidv4, err := uuid.NewV4()
	if err == nil {
		apiKey := strings.ToUpper(uuidv4.String())
		user.PasswordHash = ""
		user.ApiKeyHash, err = common.HashSecret(apiKey)
		if err == nil {
			err = configuration.UpdateUser(username, user)
			if err == nil {
				response := make(map[string]string)
				response["API-Key"] = apiKey
				log.Printf("Successfully added API-Key to user '%s'\n", username)
				render.JSON(w, r, response)
			}
		}
	} else {
		log.Printf("ERROR - Unable to add API-Key to user '%s'. Error: %s\n", username, err.Error())
		http.Error(w, "Failed to add API-Key", http.StatusInternalServerError)
	}

}
