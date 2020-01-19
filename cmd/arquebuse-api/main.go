package main

import (
	"flag"
	"github.com/arquebuse/arquebuse-api/pkg/authentication"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/arquebuse/arquebuse-api/pkg/indexer"
	"log"
	"net/http"
)

var apiVersion string
var config configuration.Config

func init() {
	configFile := flag.String("conf", "application.yaml", "Config file to load (default application.yaml.")
	configuration.Load(configFile, &config)
	authentication.InitializeJWT(&config)
	config.ApiVersion = apiVersion
}

func main() {
	router := Routes(&config)
	go indexer.Start(&config)
	log.Fatal(http.ListenAndServe(config.ListenOn, router))
}
