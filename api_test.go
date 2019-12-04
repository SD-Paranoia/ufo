package ufo

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func genKeyParts(t *testing.T) (string, string) {
	keyPair, err := openpgp.NewEntity("test", "testing key", "test@chris.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range keyPair.Identities {
		err = id.SelfSignature.SignUserId(id.UserId.Id, keyPair.PrimaryKey, keyPair.PrivateKey, nil)
		if err != nil {
			log.Fatal(err)
		}
	}

	pubbuf := &bytes.Buffer{}
	aw, err := armor.Encode(pubbuf, openpgp.PublicKeyType, nil)
	if err != nil {
		log.Fatal(err)
	}
	err = keyPair.Serialize(aw)
	if err != nil {
		t.Fatal(err)
	}
	aw.Close()
	pub := pubbuf.String()

	sigbuf := &bytes.Buffer{}
	err = openpgp.ArmoredDetachSign(sigbuf, keyPair, strings.NewReader(pub), nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, sigbuf.String()
}

func TestRegIn(t *testing.T) {
	pub, sig := genKeyParts(t)
	m := &RegisterIn{Public: pub, Sig: Sig(sig)}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	handl := MakeHandler()
	handl.Register(RegisterInHandler, Page{"/", http.MethodPost})
	srv := httptest.NewServer(handl)
	c := srv.Client()
	resp, err := c.Post(srv.URL, "application/json", bytes.NewBuffer(b))
	if err != nil {
		t.Fatal(err)
	}
	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Got %s from server", string(b))
	}
	if string(b) != "OK" {
		t.Fatalf("expected %s got %s", "OK", string(b))
	}

	resp, err = c.Post(srv.URL, "application/json", bytes.NewBuffer(b))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatal("expected 400 for dup key")
	}

	resp, err = c.Post(srv.URL, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatal("expected 400 for no body")
	}

	m.Sig = "chris"
	b, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = c.Post(srv.URL, "application/json", bytes.NewBuffer(b))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatal("expected 400 for bad sig")
	}

	m.Public = "chris"
	m.Sig = Sig(sig)
	b, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = c.Post(srv.URL, "application/json", bytes.NewBuffer(b))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatal("expected 400 for bad key")
	}
}