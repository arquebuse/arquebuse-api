package main

import (
	"flag"
	"github.com/arquebuse/arquebuse-api/pkg/authentication"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"log"
	"net/http"
)

var apiVersion string
var config configuration.Config

func init() {
	configFile := flag.String("conf", "arquebuse.yaml", "Config file to load (default arquebuse.yaml.")
	configuration.Load(configFile, &config)
	authentication.InitializeJWT(&config)
	config.ApiVersion = apiVersion
}

func main() {
	router := Routes(&config)
	log.Fatal(http.ListenAndServe(config.ListenOn, router))
}
