package main

import (
	"github.com/arquebuse/arquebuse-api/api/authentication"
	"github.com/arquebuse/arquebuse-api/api/inbound"
	"github.com/arquebuse/arquebuse-api/api/outbound"
	"github.com/arquebuse/arquebuse-api/api/spool"
	"github.com/arquebuse/arquebuse-api/api/system"
	"github.com/arquebuse/arquebuse-api/api/users"
	"github.com/arquebuse/arquebuse-api/pkg/configuration"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
)

func Routes(config *configuration.Config) *chi.Mux {
	router := chi.NewRouter()

	// Basic CORS
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // FIXME: replace with something less ... dangerous
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-API-Key"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})

	// Router configuration
	router.Use(
		render.SetContentType(render.ContentTypeJSON), // Set content-Type headers as application/json
		middleware.Logger,          // Log API request calls
		middleware.RedirectSlashes, // Redirect slashes to no slash URL versions
		middleware.Recoverer,       // Recover from panics without crashing server
		corsMiddleware.Handler,     // Handle CORS requests
	)

	router.Route("/api", func(r chi.Router) {
		r.Mount("/v1/authentication", authentication.Routes(config))
		r.Mount("/v1/inbound", inbound.Routes(config))
		r.Mount("/v1/outbound", outbound.Routes(config))
		r.Mount("/v1/spool", spool.Routes(config))
		r.Mount("/v1/system", system.Routes(config))
		r.Mount("/v1/users", users.Routes(config))
	})

	return router
}
