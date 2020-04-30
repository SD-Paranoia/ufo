package ufo_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SD-Paranoia/ufo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func genKeyPartsRSA(t *testing.T) (string, string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	a := require.New(t)
	a.Nil(err)

	pubStr, err := ufo.EncodePublicRSA(&key.PublicKey)
	a.Nil(err)

	hashed := sha256.Sum256([]byte(pubStr))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	a.Nil(err)

	sigStr := base64.StdEncoding.EncodeToString(sig)
	return pubStr, sigStr, key
}

func makeFingerPrint(pub string) ufo.FingerPrint {
	hashed := sha256.Sum256([]byte(pub))
	return ufo.FingerPrint(hex.EncodeToString(hashed[:]))
}

func signFingerPrint(t *testing.T, uuid string, key *rsa.PrivateKey) ufo.Sig {
	t.Helper()
	hashed := sha256.Sum256([]byte(uuid))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	require.Nil(t, err)
	sigStr := base64.StdEncoding.EncodeToString(sig)
	return ufo.Sig(sigStr)
}

func register(t *testing.T) (string, string, *rsa.PrivateKey) {
	t.Helper()
	pub, sig, kp := genKeyPartsRSA(t)
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
	in := &ufo.ChallengeIn{makeFingerPrint(pub)}
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
	fp := makeFingerPrint(pub)
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
	fp := makeFingerPrint(pub)
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

	t.Run("reread", func(t *testing.T) {
		b, err = json.Marshal(rin)
		req = httptest.NewRequest(http.MethodPost, "/read", bytes.NewBuffer(b))
		w = httptest.NewRecorder()
		ufo.ReadHandler(w, req)
		resp = w.Result()
		b, err = ioutil.ReadAll(resp.Body)
		require.Nil(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		rout = &ufo.ReadOut{}
		require.Nil(t, json.Unmarshal(b, rout))
		assert.Equal(t, 0, len(rout.Msgs))
	})
}

func TestRW2(t *testing.T) {
	pub1, _, kp1 := register(t)
	uuids1 := getChallenge(t, pub1)
	fp1 := makeFingerPrint(pub1)
	sfp1 := ufo.SignedFingerPrint{
		SignedChallenge: signFingerPrint(t, uuids1, kp1),
		FingerPrint:     fp1,
	}

	pub2, _, kp2 := register(t)
	uuids2 := getChallenge(t, pub2)
	fp2 := makeFingerPrint(pub2)
	sfp2 := ufo.SignedFingerPrint{
		SignedChallenge: signFingerPrint(t, uuids2, kp2),
		FingerPrint:     fp2,
	}

	gin := &ufo.GroupIn{
		Group:             ufo.Group{Members: []ufo.FingerPrint{fp1, fp2}},
		SignedFingerPrint: sfp1,
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

	const msg1 = "Hello!"
	const msg2 = "Goodbye!"

	win := &ufo.WriteIn{
		SignedFingerPrint: sfp1,
		GroupID:           gout.UUID,
		Content:           msg1,
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
	assert.Equal(t, msg1, rout.Msgs[0].Content)

	win = &ufo.WriteIn{
		SignedFingerPrint: sfp2,
		GroupID:           gout.UUID,
		Content:           msg2,
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

	rin = &ufo.ReadIn{
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
	rout = &ufo.ReadOut{}
	require.Nil(t, json.Unmarshal(b, rout))
	require.Equal(t, 2, len(rout.Msgs))
	assert.Equal(t, msg1, rout.Msgs[0].Content)
	assert.Equal(t, msg2, rout.Msgs[1].Content)

	t.Run("Reread2", func(t *testing.T) {
		b, err = json.Marshal(rin)
		req = httptest.NewRequest(http.MethodPost, "/read", bytes.NewBuffer(b))
		w = httptest.NewRecorder()
		ufo.ReadHandler(w, req)
		resp = w.Result()
		b, err = ioutil.ReadAll(resp.Body)
		require.Nil(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		rout = &ufo.ReadOut{}
		require.Nil(t, json.Unmarshal(b, rout))
		require.Equal(t, 0, len(rout.Msgs))
	})
}

func TestRegIn(t *testing.T) {
	pub, sig, _ := genKeyPartsRSA(t)
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
