package ufo

import (
	"net/http"
)

//map of request to handler translations, not to be modified during run time
var reqtrans = map[string]http.HandlerFunc{
	"/reg":   RegisterInHandler,
	"/chal":  ChallengeHandler,
	"/convo": MakeConvoHandler,
	"/read":  ReadHandler,
	"/write": WriteHandler,
	"/list":  ListHandler,
	"/log":   LogHandler,
}

//UFO is a http.HandlerFunc that routes all of
//ufo's HTTP endpoints.
func UFO(w http.ResponseWriter, r *http.Request) {
	if h, ok := reqtrans[r.URL.Path]; ok {
		login <- Event{"Request" + r.URL.Path, nil}
		h(w, r)
		return
	}
	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}
