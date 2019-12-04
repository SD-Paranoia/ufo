package ufo

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

var (
	regin    = make(chan RegisterIn)
	proofin  = make(chan Proof)
	regout   chan error
	proofout chan error

	chalin    = make(chan ChallengeIn)
	verifyin  = make(chan SignedFingerPrint)
	chalout   chan ChallengeOut
	verifyout chan error

	rin  = make(chan string)
	win  = make(chan WriteIn)
	rout chan ReadOut
	wout chan error

	groupin  = make(chan Group)
	listin   = make(chan ListIn)
	groupout chan error
	listout  chan ListOut
)

func init() {
	regout, proofout = registerProc(regin, proofin)
	rout, wout = msgProc(rin, win)
	groupout, listout = convoProc(groupin, listin)
}

func RegisterInHandler(w http.ResponseWriter, r *http.Request) {
	var in RegisterIn
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(b, &in)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	regin <- in
	if <-regout != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	w.Write([]byte("OK"))
}