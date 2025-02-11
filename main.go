package main

import (
	"goAuth/internal"
	"log"
	"net/http"
)

func main() {
	config := internal.LoadConfig()

	router := internal.NewRouter()

	internal.HandleApi(router, &config)

	address := config.GetAddress()

	log.Printf("Config path \"%s\"", internal.GetProfilePath())
	log.Printf("Listening on %s...", address)
	httpServer := &http.Server{
		Addr:    address,
		Handler: router,
	}

	err := httpServer.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
