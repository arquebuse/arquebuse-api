package spool

import (
	"encoding/json"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/arquebuse/arquebuse-api/pkg/indexer"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"
	"github.com/segmentio/ksuid"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"time"
)

var config *configuration.Config
var spoolPath string

func Routes(configuration *configuration.Config) *chi.Mux {
	config = configuration
	spoolPath = path.Join(config.DataPath, "spool")

	router := chi.NewRouter()

	// JWT protected endpoints
	router.Group(func(router chi.Router) {
		router.Use(jwtauth.Verifier(config.Security.JWTAuth))
		router.Use(jwtauth.Authenticator)
		router.Get("/", allMails)
		router.Post("/", newMail)
		router.Get("/{id}", oneMail)
	})

	return router
}

// Return all Mail (few details)
func allMails(w http.ResponseWriter, r *http.Request) {
	indexPath := path.Join(spoolPath, "index.json")
	response, err := indexer.LoadIndex(indexPath)
	if err != nil {
		log.Fatalf("spool - Failed to load index from folder '%s'. Error: %s", spoolPath, err.Error())
	}

	render.JSON(w, r, response)
}

// Return all Mail (few details)
func oneMail(w http.ResponseWriter, r *http.Request) {

	id := chi.URLParam(r, "id")
	mailPath := path.Join(spoolPath, id+".json")
	response, err := indexer.LoadMail(mailPath)
	if err != nil {
		log.Fatalf("spool - Failed to load mail '%s'. Error: %s", mailPath, err.Error())
	}

	render.JSON(w, r, response)
}

// Add a new mail in the spool
func newMail(w http.ResponseWriter, r *http.Request) {

	type spoolMail struct {
		Timestamp time.Time `json:"timestamp"`
		Server    string    `json:"server"`
		From      string    `json:"from"`
		To        string    `json:"to"`
		Data      string    `json:"data"`
		Status    string    `json:"status"`
	}

	var mail spoolMail
	err := json.NewDecoder(r.Body).Decode(&mail)
	if err != nil {
		http.Error(w, "Unable to decode request", http.StatusBadRequest)
		return
	}

	// FIXME: validate input ...

	mail.Timestamp = time.Now()
	mail.Status = "NEW"

	filePath := path.Join(spoolPath, ksuid.New().String()+".json")

	file, err := json.MarshalIndent(mail, "", " ")
	if err != nil {
		log.Fatalf("Spool - Failed to convert to JSON current mail. Error: %s\n", err.Error())
	}

	err = ioutil.WriteFile(filePath, file, 0644)
	if err != nil {
		log.Fatalf("Spool - Failed to update file in '%s'. Error: %s\n", filePath, err.Error())
	}

	render.PlainText(w, r, "Mail added to the spool")
}
