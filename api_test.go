package ufo_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SD-Paranoia/ufo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func genKeyParts(t *testing.T) (string, string, *openpgp.Entity) {
	t.Helper()
	keyPair, err := openpgp.NewEntity("test", "testing key", "test@chris.com", nil)
	a := require.New(t)
	a.Nil(err)

	for _, id := range keyPair.Identities {
		err = id.SelfSignature.SignUserId(id.UserId.Id, keyPair.PrimaryKey, keyPair.PrivateKey, nil)
		a.Nil(err)
	}

	pubbuf := &bytes.Buffer{}
	aw, err := armor.Encode(pubbuf, openpgp.PublicKeyType, nil)
	a.Nil(err)
	err = keyPair.Serialize(aw)
	a.Nil(err)
	aw.Close()
	pub := pubbuf.String()

	sigbuf := &bytes.Buffer{}
	a.Nil(openpgp.ArmoredDetachSign(sigbuf, keyPair, strings.NewReader(pub), nil))
	return pub, sigbuf.String(), keyPair
}

func signFingerPrint(t *testing.T, uuid string, keyPair *openpgp.Entity) ufo.Sig {
	t.Helper()
	sigbuf := &bytes.Buffer{}
	require.Nil(t, openpgp.ArmoredDetachSign(sigbuf, keyPair, strings.NewReader(uuid), nil))
	return ufo.Sig(sigbuf.String())
}

func TestChallenge(t *testing.T) {
	pub, sig, kp := genKeyParts(t)

	//Register ourselves first
	m := &ufo.RegisterIn{Public: pub, Sig: ufo.Sig(sig)}
	b, err := json.Marshal(m)
	require.Nil(t, err)
	req := httptest.NewRequest(http.MethodPost, "/reg", bytes.NewBuffer(b))
	w := httptest.NewRecorder()
	ufo.RegisterInHandler(w, req)
	require.Nil(t, err)
	resp := w.Result()
	assert.Equal(t, 200, resp.StatusCode)

	in := &ufo.ChallengeIn{ufo.MakeFingerPrint(pub)}
	b, err = json.Marshal(in)
	require.Nil(t, err)
	req = httptest.NewRequest(http.MethodPost, "/chal", bytes.NewBuffer(b))
	w = httptest.NewRecorder()
	ufo.ChallengeHandler(w, req)
	resp = w.Result()
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var out ufo.ChallengeOut
	require.Nil(t, json.Unmarshal(b, &out))
	_, err = uuid.Parse(out.UUID)
	assert.Nilf(t, err, "Got err %s", out.UUID)

	//Attempt to create a new group with ourself; this might become an error later
	fp := ufo.MakeFingerPrint(pub)
	gin := &ufo.GroupIn{
		Group: ufo.Group{Members: []ufo.FingerPrint{fp}},
		SignedFingerPrint: ufo.SignedFingerPrint{
			SignedChallenge: signFingerPrint(t, out.UUID, kp),
			FingerPrint:     fp,
		},
	}
	b, err = json.Marshal(gin)
	require.Nil(t, err)
	req = httptest.NewRequest(http.MethodPost, "/convo", bytes.NewBuffer(b))
	w = httptest.NewRecorder()
	ufo.MakeConvoHandler(w, req)
	resp = w.Result()
	assert.Equal(t, 200, resp.StatusCode)
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	gout := &ufo.GroupOut{}
	require.Nil(t, json.Unmarshal(b, gout))
	assert.Empty(t, gout.Error)
	_, err = uuid.Parse(gout.UUID)
	assert.Nil(t, err)

}

func TestRegIn(t *testing.T) {
	pub, sig, _ := genKeyParts(t)
	m := &ufo.RegisterIn{Public: pub, Sig: ufo.Sig(sig)}
	b, err := json.Marshal(m)
	require.Nil(t, err)

	req := httptest.NewRequest(http.MethodPost, "/reg", bytes.NewBuffer(b))
	w := httptest.NewRecorder()
	ufo.RegisterInHandler(w, req)
	resp := w.Result()

	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "OK", string(b))

	t.Run("Duplicate key", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		ufo.RegisterInHandler(w, req)
		resp := w.Result()
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("nil body", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/reg", nil)
		ufo.RegisterInHandler(w, req)
		resp := w.Result()
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("bad sig", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		m := &ufo.RegisterIn{Public: pub, Sig: ufo.Sig("chris")}
		b, err = json.Marshal(m)
		require.Nil(t, err)
		req := httptest.NewRequest(http.MethodPost, "/reg", bytes.NewBuffer(b))
		ufo.RegisterInHandler(w, req)
		resp := w.Result()
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("bad key", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		m := &ufo.RegisterIn{Public: "chris", Sig: ufo.Sig(sig)}
		b, err = json.Marshal(m)
		require.Nil(t, err)
		req := httptest.NewRequest(http.MethodPost, "/reg", bytes.NewBuffer(b))
		ufo.RegisterInHandler(w, req)
		resp := w.Result()
		assert.Equal(t, 400, resp.StatusCode)
	})
}