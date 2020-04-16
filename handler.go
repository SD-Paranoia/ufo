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
}

//UFO is a http.HandlerFunc that routes all of
//ufo's HTTP endpoints.
func UFO(w http.ResponseWriter, r *http.Request) {
	/* All of our end points are POST only */
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if h, ok := reqtrans[r.URL.Path]; ok {
		h(w, r)
		return
	}
	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}
