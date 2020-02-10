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

func register(t *testing.T) (string, string, *openpgp.Entity) {
	t.Helper()
	pub, sig, kp := genKeyParts(t)
	m := &ufo.RegisterIn{Public: pub, Sig: ufo.Sig(sig)}
	b, err := json.Marshal(m)
	require.Nil(t, err)
	req := httptest.NewRequest(http.MethodPost, "/reg", bytes.NewBuffer(b))
	w := httptest.NewRecorder()
	ufo.RegisterInHandler(w, req)
	require.Nil(t, err)
	resp := w.Result()
	require.Equal(t, 200, resp.StatusCode)
	b, _ = ioutil.ReadAll(resp.Body)
	assert.Equal(t, "OK", string(b))
	return pub, sig, kp
}

func getChallenge(t *testing.T, pub string) string {
	t.Helper()
	in := &ufo.ChallengeIn{ufo.MakeFingerPrint(pub)}
	b, err := json.Marshal(in)
	require.Nil(t, err)
	req := httptest.NewRequest(http.MethodPost, "/chal", bytes.NewBuffer(b))
	w := httptest.NewRecorder()
	ufo.ChallengeHandler(w, req)
	resp := w.Result()
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var out ufo.ChallengeOut
	require.Nil(t, json.Unmarshal(b, &out))
	_, err = uuid.Parse(out.UUID)
	assert.Nilf(t, err, "Got err %s", out.UUID)
	return out.UUID
}

func TestMakeGroup(t *testing.T) {
	pub, _, kp := register(t)
	uuids := getChallenge(t, pub)
	//Attempt to create a new group with ourself; this might become an error later
	fp := ufo.MakeFingerPrint(pub)
	gin := &ufo.GroupIn{
		Group: ufo.Group{Members: []ufo.FingerPrint{fp}},
		SignedFingerPrint: ufo.SignedFingerPrint{
			SignedChallenge: signFingerPrint(t, uuids, kp),
			FingerPrint:     fp,
		},
	}
	b, err := json.Marshal(gin)
	require.Nil(t, err)
	req := httptest.NewRequest(http.MethodPost, "/convo", bytes.NewBuffer(b))
	w := httptest.NewRecorder()
	ufo.MakeConvoHandler(w, req)
	resp := w.Result()
	assert.Equal(t, 200, resp.StatusCode)
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	gout := &ufo.GroupOut{}
	require.Nil(t, json.Unmarshal(b, gout))
	assert.Empty(t, gout.Error)
	_, err = uuid.Parse(gout.UUID)
	assert.Nil(t, err)

	//Make sure out group list now has our newly created UUID
	//It is possible for our signed fingerprint to expire, but not likely
	lin := &ufo.ListIn{
		gin.SignedFingerPrint,
	}
	b, err = json.Marshal(lin)
	require.Nil(t, err)
	req = httptest.NewRequest(http.MethodPost, "/list", bytes.NewBuffer(b))
	w = httptest.NewRecorder()
	ufo.ListHandler(w, req)
	resp = w.Result()
	assert.Equal(t, 200, resp.StatusCode)
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	lout := &ufo.ListOut{}
	require.Nil(t, json.Unmarshal(b, lout))
	assert.Equal(t, 1, len(lout.GroupUUIDs))
	assert.Equal(t, gout.UUID, lout.GroupUUIDs[0])
}

func TestRW(t *testing.T) {
	pub, _, kp := register(t)
	uuids := getChallenge(t, pub)
	//Attempt to create a new group with ourself; this might become an error later
	fp := ufo.MakeFingerPrint(pub)
	gin := &ufo.GroupIn{
		Group: ufo.Group{Members: []ufo.FingerPrint{fp}},
		SignedFingerPrint: ufo.SignedFingerPrint{
			SignedChallenge: signFingerPrint(t, uuids, kp),
			FingerPrint:     fp,
		},
	}
	b, err := json.Marshal(gin)
	require.Nil(t, err)
	req := httptest.NewRequest(http.MethodPost, "/convo", bytes.NewBuffer(b))
	w := httptest.NewRecorder()
	ufo.MakeConvoHandler(w, req)
	resp := w.Result()
	assert.Equal(t, 200, resp.StatusCode)
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	gout := &ufo.GroupOut{}
	require.Nil(t, json.Unmarshal(b, gout))
	assert.Empty(t, gout.Error)

	const msgContent = "Hello from paranoia land"

	win := &ufo.WriteIn{
		SignedFingerPrint: gin.SignedFingerPrint,
		GroupID:           gout.UUID,
		Content:           msgContent,
	}
	b, err = json.Marshal(win)
	req = httptest.NewRequest(http.MethodPost, "/write", bytes.NewBuffer(b))
	w = httptest.NewRecorder()
	ufo.WriteHandler(w, req)
	resp = w.Result()
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "OK", string(b))

	rin := &ufo.ReadIn{
		SignedFingerPrint: win.SignedFingerPrint,
		GroupID:           gout.UUID,
	}
	b, err = json.Marshal(rin)
	req = httptest.NewRequest(http.MethodPost, "/read", bytes.NewBuffer(b))
	w = httptest.NewRecorder()
	ufo.ReadHandler(w, req)
	resp = w.Result()
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	rout := &ufo.ReadOut{}
	require.Nil(t, json.Unmarshal(b, rout))
	assert.Equal(t, 1, len(rout.Msgs))
	assert.Equal(t, msgContent, rout.Msgs[0].Content)
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
