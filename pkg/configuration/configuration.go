package configuration

import (
	"errors"
	"github.com/arquebuse/arquebuse-api/pkg/common"
	"github.com/go-chi/jwtauth"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"path"
)

// Configuration data
type Config struct {
	ApiVersion string
	ListenOn   string `yaml:"listenOn"`
	DataPath   string `yaml:"dataPath"`
	Security   struct {
		UserFile string           `yaml:"userFile"`
		JWTAuth  *jwtauth.JWTAuth `yaml:"-"`
	} `yaml:"security"`
}

// User for internal usage
type PrivateUser struct {
	FullName     string   `yaml:"fullName"`
	PasswordHash string   `yaml:"passwordHash"`
	ApiKeyHash   string   `yaml:"apiKeyHash"`
	Roles        []string `yaml:"roles"`
}

var config *Config
var users map[string]*PrivateUser

// Search for a config file in multiple locations
func SearchFile(fileName string) string {
	// Search Paths
	searchPaths := []string{
		"",
		"./",
		"./conf/",
		"/etc/arquebuse-api/",
	}

	for _, searchPath := range searchPaths {
		currentPath := path.Join(searchPath, fileName)
		if common.FileExists(currentPath) {
			return currentPath
		}
	}

	return ""
}

// Load a config file
func Load(configFile *string, configuration *Config) {
	// Default values
	configuration.ListenOn = "127.0.0.1:8080"
	configuration.DataPath = "./data"

	p := SearchFile(*configFile)
	if p != "" {
		c, err := ioutil.ReadFile(p)
		if err != nil {
			log.Printf("ERROR - Unable to read config file '%s'. Error: %s\n", p, err.Error())
		} else {
			err := yaml.Unmarshal(c, configuration)
			if err != nil {
				log.Printf("ERROR - Failed to parse config file '%s'. Error: %s\n", p, err.Error())
			} else {
				log.Printf("Successfully loaded config file '%s'\n", p)
			}
		}
	} else {
		log.Print("No config file found\n")
	}

	// Default values
	if configuration.Security.UserFile == "" {
		configuration.Security.UserFile = path.Join(configuration.DataPath, "users.yaml")
	}
}

// Init user file
func initUsers(userFile string) error {
	passwordHash, err := common.HashSecret(`arquebuse`)

	if err != nil {
		return err
	}

	initialUser := PrivateUser{
		PasswordHash: passwordHash,
		FullName:     `Arquebuse`,
		Roles:        []string{`admin`},
	}

	users = make(map[string]*PrivateUser)
	users[`arquebuse`] = &initialUser

	return saveUsers(userFile)
}

// Load users from user file
func LoadUsers(userFile string) {

	if common.FileExists(userFile) {
		c, err := ioutil.ReadFile(userFile)
		if err != nil {
			log.Fatalf("ERROR - Unable to read user file '%s'. Error: %s\n", userFile, err.Error())
		} else {
			err := yaml.Unmarshal(c, &users)
			if err != nil {
				log.Fatalf("ERROR - Failed to parse user file '%s'. Error: %s\n", userFile, err.Error())
			}
		}

		log.Printf("Successfully loaded %d user(s) from '%s'\n", len(users), userFile)

	} else {
		err := initUsers(userFile)

		if err != nil {
			log.Fatalf("ERROR - Unable to initialize user file '%s'. Error: %s\n", userFile, err.Error())
		}
	}
}

// Save users into user file
func saveUsers(userFile string) error {

	content, err := yaml.Marshal(&users)
	if err != nil {
		return err
	}

	mode := os.FileMode(0640)
	if common.FileExists(userFile) {
		fileInfo, err := os.Stat(userFile)
		if err != nil {
			return err
		}

		mode = fileInfo.Mode()
	}

	err = ioutil.WriteFile(userFile, content, mode)
	if err != nil {
		return err
	}

	log.Printf("Successfully saved %d user(s) to '%s'\n", len(users), userFile)
	return nil
}

// Get all users
func Users() map[string]*PrivateUser {
	return users
}

// Get a user
func User(username string) (PrivateUser, error) {
	var authentications []string

	if user, ok := users[username]; ok {
		if user.ApiKeyHash != "" {
			authentications = append(authentications, "API-Key")
		}

		if user.PasswordHash != "" {
			authentications = append(authentications, "Password")
		}

		return *users[username], nil
	} else {
		return PrivateUser{}, errors.New("user not found")
	}
}

// Update a user
func UpdateUser(username string, user PrivateUser) error {

	if _, ok := users[username]; ok {
		users[username] = &user
	} else {
		return errors.New("user '" + username + "' does't exist")
	}

	return saveUsers(config.Security.UserFile)
}

// Add a user
func AddUser(username string, user PrivateUser) error {

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
func DeleteUser(username string) error {

	if _, ok := users[username]; ok {
		delete(users, username)
	} else {
		return errors.New("user '" + username + "' does't exist")
	}

	return saveUsers(config.Security.UserFile)
}
