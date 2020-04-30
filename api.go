package ufo

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

var (
	regin    = make(chan RegisterIn)
	proofin  = make(chan proof)
	regout   chan error
	proofout chan error

	chalin    = make(chan ChallengeIn)
	verifyin  = make(chan SignedFingerPrint)
	chalout   chan ChallengeOut
	verifyout chan error

	readin   = make(chan ReadIn)
	writein  = make(chan WriteIn)
	readout  chan ReadOut
	writeout chan error

	groupin  = make(chan Group)
	listin   = make(chan ListIn)
	groupout chan GroupOut
	listout  chan ListOut

	login = make(chan Event)
)

func init() {
	regout, proofout = registerProc(regin, proofin)
	readout, writeout = msgProc(readin, writein)
	groupout, listout = convoProc(groupin, listin)
	chalout, verifyout = challengeProc(chalin, verifyin)
	logger(login)
	login <- Event{"started", nil}
}

//RegisterInHandler is the endpoint for registration requests
//it accepts a marshalled RegisterIn struct and returns
//a 200 status code on success.
func RegisterInHandler(w http.ResponseWriter, r *http.Request) {
	var in RegisterIn
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		login <- Event{"Reading POST", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(b, &in)
	if err != nil {
		login <- Event{"Parsing JSON", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	regin <- in
	if err = <-regout; err != nil {
		login <- Event{"Registration", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	w.Write([]byte("OK"))
}

//ChallengeHandler is the endpoint for challenge requests
//it accepts a json marshalled ChallengeIn struct and
//returns a marshalled ChallengeOut on success.
func ChallengeHandler(w http.ResponseWriter, r *http.Request) {
	var in ChallengeIn
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		login <- Event{"Reading POST", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(b, &in)
	if err != nil {
		login <- Event{"Parsing JSON", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	chalin <- in
	out := <-chalout
	if out.UUID == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	b, _ = json.Marshal(&out)
	w.Write(b)
}

//MakeConvoHandler is the endpoint for creation of
//conversations, it accepts a json marshalled GroupIn
//struct and returns a marshalled GroupOut struct on success.
func MakeConvoHandler(w http.ResponseWriter, r *http.Request) {
	var in GroupIn
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		login <- Event{"Reading POST", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(b, &in)
	if err != nil {
		login <- Event{"Parsing JSON", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	verifyin <- in.SignedFingerPrint
	err = <-verifyout
	if err != nil {
		login <- Event{"Verification", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	groupin <- in.Group
	out := <-groupout
	b, _ = json.Marshal(&out)
	w.Write(b)
}

//ReadHandler is the endpoint for requesting messages from
//the server. It accepts a marshalled ReadIn struct and
//returns a marshalled ReadOut struct on success.
func ReadHandler(w http.ResponseWriter, r *http.Request) {
	var in ReadIn
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		login <- Event{"Reading POST", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(b, &in)
	if err != nil {
		login <- Event{"Parsing JSON", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	verifyin <- in.SignedFingerPrint
	err = <-verifyout
	if err != nil {
		login <- Event{"Verification", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	readin <- in
	out := <-readout
	if out.Err != nil {
		login <- Event{"Read", out.Err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	b, _ = json.Marshal(&out)
	w.Write(b)
}

//WriteHandler is the endpoint for writing messages
//to a group. It accepts a WriteIn struct and returns a
//200 status code on success with a body of "OK"
func WriteHandler(w http.ResponseWriter, r *http.Request) {
	var in WriteIn
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		login <- Event{"Reading POST", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(b, &in)
	if err != nil {
		login <- Event{"Parsing JSON", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	verifyin <- in.SignedFingerPrint
	err = <-verifyout
	if err != nil {
		login <- Event{"Verification", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	writein <- in
	out := <-writeout
	if out != nil {
		login <- Event{"Write", out}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	w.Write([]byte("OK"))
}

//ListHandler is the endpoint for users to query what
//groups they are a part of. It accepts a ListIn struct
//and returns a ListOut struct.
func ListHandler(w http.ResponseWriter, r *http.Request) {
	var in ListIn
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		login <- Event{"Reading POST", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(b, &in)
	if err != nil {
		login <- Event{"Parsing JSON", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	verifyin <- in.SignedFingerPrint
	err = <-verifyout
	if err != nil {
		login <- Event{"Verification", err}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	listin <- in
	out := <-listout
	b, _ = json.Marshal(&out)
	w.Write(b)
}
