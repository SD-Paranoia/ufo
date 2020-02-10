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

	readin   = make(chan string)
	writein  = make(chan WriteIn)
	readout  chan ReadOut
	writeout chan error

	groupin  = make(chan Group)
	listin   = make(chan ListIn)
	groupout chan GroupOut
	listout  chan ListOut
)

func init() {
	regout, proofout = registerProc(regin, proofin)
	readout, writeout = msgProc(readin, writein)
	groupout, listout = convoProc(groupin, listin)
	chalout, verifyout = challengeProc(chalin, verifyin)
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

func ChallengeHandler(w http.ResponseWriter, r *http.Request) {
	var in ChallengeIn
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
	chalin <- in
	out := <-chalout
	if out.UUID == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	b, err = json.Marshal(&out)
	w.Write(b)
}

func MakeConvoHandler(w http.ResponseWriter, r *http.Request) {
	var in GroupIn
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
	verifyin <- in.SignedFingerPrint
	err = <-verifyout
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	groupin <- in.Group
	out := <-groupout
	b, err = json.Marshal(&out)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	w.Write(b)
}

func ReadHandler(w http.ResponseWriter, r *http.Request) {
	var in ReadIn
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
	verifyin <- in.SignedFingerPrint
	err = <-verifyout
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	readin <- in.GroupID
	out := <-readout
	b, err = json.Marshal(&out)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	w.Write(b)
}

func WriteHandler(w http.ResponseWriter, r *http.Request) {
	var in WriteIn
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
	verifyin <- in.SignedFingerPrint
	err = <-verifyout
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	writein <- in
	out := <-writeout
	if out != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	w.Write([]byte("OK"))
}

func ListHandler(w http.ResponseWriter, r *http.Request) {
	var in ListIn
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
	verifyin <- in.SignedFingerPrint
	err = <-verifyout
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	listin <- in
	out := <-listout
	b, err = json.Marshal(&out)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	w.Write(b)
}
