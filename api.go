package ufo

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/crypto/openpgp"
)

var ledger *Ledger

func init() {
	ledger = NewLedger()
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
	pub, err := ledger.AddKey(in.Public)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err = openpgp.CheckArmoredDetachedSignature(openpgp.EntityList{pub}, strings.NewReader(in.Public), strings.NewReader(string(in.Sig)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte("OK"))
}