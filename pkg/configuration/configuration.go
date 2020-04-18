package configuration

import (
	"github.com/arquebuse/arquebuse-api/pkg/common"
	"github.com/go-chi/jwtauth"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

type Config struct {
	ApiVersion string
	ListenOn   string `yaml:"listenOn"`
	DataPath   string `yaml:"dataPath"`
	Security   struct {
		UserFile string           `yaml:"userFile"`
		JWTAuth  *jwtauth.JWTAuth `yaml:"-"`
	} `yaml:"security"`
}

func SearchFile(fileName string) string {
	// Search Paths
	searchPaths := []string{
		"",
		"./",
		"./conf/",
		"/etc/arquebuse-api/",
	}

	for _, path := range searchPaths {
		currentPath := path + fileName
		if common.FileExists(currentPath) {
			return currentPath
		}
	}

	return ""
}

func Load(configFile *string, configuration *Config) {
	// Default values
	configuration.ListenOn = "127.0.0.1:8080"
	configuration.Security.UserFile = "users.yaml"

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
}
