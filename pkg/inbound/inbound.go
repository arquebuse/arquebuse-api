package inbound

import (
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/arquebuse/arquebuse-api/pkg/indexer"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"
	"github.com/jhillyerd/enmime"
	"log"
	"net/http"
	"path"
	"strings"
	"time"
)

var config *configuration.Config
var inboundPath string

type header struct {
	Key    string   `json:"id"`
	Values []string `json:"values"`
}

type parsedEmail struct {
	ID          string    `json:"id"`
	Received    time.Time `json:"timestamp"`
	Client      string    `json:"client,omitempty"`
	From        string    `json:"from"`
	To          string    `json:"to"`
	Subject     string    `json:"subject"`
	Data        string    `json:"data,omitempty"`
	Parsed      bool      `json:"parsed"`
	Text        string    `json:"text"`
	Html        string    `json:"html"`
	Headers     []header  `json:"headers"`
	ParseErrors []string  `json:"parseErrors"`
}

func Routes(configuration *configuration.Config) *chi.Mux {
	config = configuration
	inboundPath = path.Join(config.DataPath, "inbound")

	router := chi.NewRouter()

	// JWT protected endpoints
	router.Group(func(router chi.Router) {
		router.Use(jwtauth.Verifier(config.Security.JWTAuth))
		router.Use(jwtauth.Authenticator)
		router.Get("/", allMails)
		router.Get("/{id}", oneMail)
	})

	return router
}

// Return all Mail (few details)
func allMails(w http.ResponseWriter, r *http.Request) {
	indexPath := path.Join(inboundPath, "index.json")
	response, err := indexer.LoadIndex(indexPath)
	if err != nil {
		log.Printf("Inbound - Failed to load index from folder '%s'. Error: %s", inboundPath, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	render.JSON(w, r, response)
}

// Return all Mail (few details)
func oneMail(w http.ResponseWriter, r *http.Request) {

	id := chi.URLParam(r, "id")
	mailPath := path.Join(inboundPath, id+".json")
	mail, err := indexer.LoadMail(mailPath)
	if err != nil {
		log.Printf("Inbound - Failed to load mail '%s'. Error: %s", mailPath, err.Error())
		http.Error(w, "Mail not found", http.StatusNotFound)
		return
	}

	response := parsedEmail{
		ID:          mail.ID,
		Received:    mail.Received,
		Client:      mail.Client,
		From:        mail.From,
		To:          mail.To,
		Subject:     mail.Subject,
		Data:        mail.Data,
		Parsed:      false,
		ParseErrors: make([]string, 0),
		Headers:     make([]header, 0),
	}

	envelope, err := enmime.ReadEnvelope(strings.NewReader(mail.Data))
	if err == nil {
		response.Text = envelope.Text
		response.Html = envelope.HTML

		for _, key := range envelope.GetHeaderKeys() {
			response.Headers = append(response.Headers, header{
				Key:    key,
				Values: envelope.GetHeaderValues(key),
			})
		}

		for _, parseError := range envelope.Errors {
			response.ParseErrors = append(response.ParseErrors, parseError.String())
		}

		response.Parsed = true

	} else {
		log.Printf("Inbound - Failed to parse data from email '%s'. Error: %s", id, err.Error())
		response.ParseErrors = append(response.ParseErrors, err.Error())
	}

	render.JSON(w, r, response)
}
