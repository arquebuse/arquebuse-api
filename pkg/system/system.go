package system

import (
	"github.com/abrander/go-supervisord"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"
	"github.com/matishsiao/goInfo"
	"net/http"
	"strconv"
	"strings"
)

var config *configuration.Config

func Routes(configuration *configuration.Config) *chi.Mux {
	config = configuration
	router := chi.NewRouter()

	// JWT protected endpoints
	router.Group(func(router chi.Router) {
		router.Use(jwtauth.Verifier(config.Security.JWTAuth))
		router.Use(jwtauth.Authenticator)
		router.Get("/applications", getAllApplications)
		router.Get("/applications/{apName}", getApplication)
		router.Post("/applications/{apName}/start", startApplication)
	})

	// Unprotected endpoints
	router.Group(func(router chi.Router) {
		router.Get("/info", getInfo)
	})

	return router
}

// Get hostname from os
func getInfo(w http.ResponseWriter, r *http.Request) {

	gi := goInfo.GetInfo()

	response := make(map[string]string)
	response["hostname"] = gi.Hostname
	response["apiVersion"] = config.ApiVersion
	response["core"] = gi.Core
	response["cpus"] = strconv.Itoa(gi.CPUs)
	response["goOs"] = gi.GoOS
	response["kernel"] = gi.Kernel
	response["os"] = gi.OS
	response["platform"] = gi.Platform

	render.JSON(w, r, response)
}

// Handler to supervisord API
func getClient() *supervisord.Client {
	c, err := supervisord.NewClient("http://127.0.0.1:9001/RPC2")
	if err != nil {
		panic(err.Error())
	}

	return c
}

// Get all applications from supervisord
func getAllApplications(w http.ResponseWriter, r *http.Request) {

	client := getClient()
	list, err := client.GetAllProcessInfo()

	if err != nil {
		panic(err)
	}

	render.JSON(w, r, list)
}

// Get an application from supervisord
func getApplication(w http.ResponseWriter, r *http.Request) {

	appName := chi.URLParam(r, "apName")
	client := getClient()
	info, err := client.GetProcessInfo(appName)

	if err != nil {
		if strings.Contains(err.Error(), "BAD_NAME") {
			http.Error(w, http.StatusText(404), 404)
			return
		} else {
			panic(err.Error())
		}
	}

	render.JSON(w, r, info)
}

// Start an application in supervisord
func startApplication(w http.ResponseWriter, r *http.Request) {

	appName := chi.URLParam(r, "apName")
	client := getClient()
	app, err := client.GetProcessInfo(appName)

	if err != nil {
		if strings.Contains(err.Error(), "BAD_NAME") {
			http.Error(w, "Application not found", http.StatusNotFound)
			return
		} else {
			panic(err.Error())
		}
	}

	if app.State == supervisord.StateRunning {
		http.Error(w, "Application already started", http.StatusBadRequest)
		return
	}

	wait := r.URL.Query().Get("wait")

	if wait == "true" {
		err = client.StartProcess(appName, true)
		if err != nil {
			panic(err.Error())
		}

		w.WriteHeader(http.StatusOK)
		render.PlainText(w, r, "Application started")
	} else {
		err = client.StartProcess(appName, false)
		if err != nil {
			panic(err.Error())
		}

		w.WriteHeader(http.StatusCreated)
		render.PlainText(w, r, "Application is starting ...")
	}
}
