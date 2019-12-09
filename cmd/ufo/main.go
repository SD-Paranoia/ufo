package main

import (
	"log"
	"net/http"

	"github.com/SD-Paranoia/ufo"
)

func main() {
	handl := ufo.MakeHandler()
	handl.Register(ufo.RegisterInHandler, ufo.Page{"/reg", http.MethodPost})
	handl.Register(ufo.ChallengeHandler, ufo.Page{"/chal", http.MethodPost})
	handl.Register(ufo.MakeConvoHandler, ufo.Page{"/convo", http.MethodPost})
	log.Fatal(http.ListenAndServe(":8080", handl))
}