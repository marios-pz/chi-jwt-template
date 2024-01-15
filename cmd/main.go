package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"

	token_manager "github.com/marios-pz/document-uploader/internal"
)

func main() {
	tm := token_manager.NewTokenManager("amogus-twerk")

	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/")) // for load balancer and uptime external services
	r.Use(middleware.Logger)

	r.Route("/api", func(r chi.Router) {
		// Private route
		r.Group(func(r chi.Router) {
			r.Use(tm.JWTHandler)
			r.Mount("/debug", middleware.Profiler())
		})

		// Public route
		r.Get("/ping", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("amogus"))
			return
		})
	})

	err := http.ListenAndServe(":8080", r)
	if err != nil {
		log.Println("There was an error listening on port :8080", err)
	}
}
