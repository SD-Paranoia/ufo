package main

import (
	"log"
	"net/http"
	"time"

	"github.com/SD-Paranoia/ufo"
)

func main() {
	s := &http.Server{
		Addr:         ":8080",
		Handler:      http.HandlerFunc(ufo.UFO),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Fatal(s.ListenAndServe())
}