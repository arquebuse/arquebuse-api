package outbound

import (
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/arquebuse/arquebuse-api/pkg/indexer"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"
	"log"
	"net/http"
	"os"
	"path"
)

var config *configuration.Config
var outboundPath string

func Routes(configuration *configuration.Config) *chi.Mux {
	config = configuration
	outboundPath = path.Join(config.DataPath, "outbound")

	router := chi.NewRouter()

	// JWT protected endpoints
	router.Group(func(router chi.Router) {
		router.Use(jwtauth.Verifier(config.Security.JWTAuth))
		router.Use(jwtauth.Authenticator)
		router.Get("/", allMails)
		router.Get("/{id}", oneMail)
		router.Delete("/{id}", deleteOneMail)
	})

	return router
}

// Return all Mail (few details)
func allMails(w http.ResponseWriter, r *http.Request) {
	indexPath := path.Join(outboundPath, "index.json")
	response, err := indexer.LoadIndex(indexPath)
	if err != nil {
		log.Printf("outbound - Failed to load index from folder '%s'. Error: %s", outboundPath, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	render.JSON(w, r, response)
}

// Return all Mail (few details)
func oneMail(w http.ResponseWriter, r *http.Request) {

	id := chi.URLParam(r, "id")
	mailPath := path.Join(outboundPath, id+".json")
	response, err := indexer.LoadMail(mailPath)
	if err != nil {
		log.Printf("Inbound - Failed to load mail '%s'. Error: %s", mailPath, err.Error())
		http.Error(w, "Mail not found", http.StatusNotFound)
	}

	render.JSON(w, r, response)
}

// Delete one Mail
func deleteOneMail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	mailPath := path.Join(outboundPath, id+".json")
	err := os.Remove(mailPath)
	if err != nil {
		log.Printf("ERROR - Unable to delete outbound item '%s'\n", id)
		http.Error(w, "Cannot delete item", http.StatusInternalServerError)
	} else {
		log.Printf("Successfully deleted outbound item '%s'\n", id)
		render.PlainText(w, r, "Item successfully deleted")
	}
}
