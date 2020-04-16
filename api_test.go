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
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/SD-Paranoia/ufo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _jsontransaction bool = false

func marshalLog(t *testing.T, v interface{}) ([]byte, error) {
	if _jsontransaction {
		fmt.Println(t.Name() + " Sending:")
		b, _ := json.MarshalIndent(v, "", "\t")
		fmt.Print(string(b))
		fmt.Print("\n")
	}
	return json.Marshal(v)
}

func unmarshalLog(t *testing.T, b []byte, v interface{}) error {
	if _jsontransaction {
		fmt.Println(t.Name() + " Receiving:")
		var out bytes.Buffer
		json.Indent(&out, b, "", "\t")
		fmt.Println(string(out.Bytes()))
	}
	return json.Unmarshal(b, v)
}

func TestMain(m *testing.M) {
	flag.BoolVar(&_jsontransaction, "log", false, "logs json transactions")
	flag.Parse()
	os.Exit(m.Run())
}

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
	b, err := marshalLog(t, m)
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
	b, err := marshalLog(t, in)
	require.Nil(t, err)
	req := httptest.NewRequest(http.MethodPost, "/chal", bytes.NewBuffer(b))
	w := httptest.NewRecorder()
	ufo.ChallengeHandler(w, req)
	resp := w.Result()
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var out ufo.ChallengeOut
	require.Nil(t, unmarshalLog(t, b, &out))
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
	b, err := marshalLog(t, gin)
	require.Nil(t, err)
	req := httptest.NewRequest(http.MethodPost, "/convo", bytes.NewBuffer(b))
	w := httptest.NewRecorder()
	ufo.MakeConvoHandler(w, req)
	resp := w.Result()
	assert.Equal(t, 200, resp.StatusCode)
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	gout := &ufo.GroupOut{}
	require.Nil(t, unmarshalLog(t, b, gout))
	assert.Empty(t, gout.Error)
	_, err = uuid.Parse(gout.UUID)
	assert.Nil(t, err)

	//Make sure out group list now has our newly created UUID
	//It is possible for our signed fingerprint to expire, but not likely
	lin := &ufo.ListIn{
		gin.SignedFingerPrint,
	}
	b, err = marshalLog(t, lin)
	require.Nil(t, err)
	req = httptest.NewRequest(http.MethodPost, "/list", bytes.NewBuffer(b))
	w = httptest.NewRecorder()
	ufo.ListHandler(w, req)
	resp = w.Result()
	assert.Equal(t, 200, resp.StatusCode)
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	lout := &ufo.ListOut{}
	require.Nil(t, unmarshalLog(t, b, lout))
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
	b, err := marshalLog(t, gin)
	require.Nil(t, err)
	req := httptest.NewRequest(http.MethodPost, "/convo", bytes.NewBuffer(b))
	w := httptest.NewRecorder()
	ufo.MakeConvoHandler(w, req)
	resp := w.Result()
	assert.Equal(t, 200, resp.StatusCode)
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	gout := &ufo.GroupOut{}
	require.Nil(t, unmarshalLog(t, b, gout))
	assert.Empty(t, gout.Error)

	const msgContent = "Hello from paranoia land"

	win := &ufo.WriteIn{
		SignedFingerPrint: gin.SignedFingerPrint,
		GroupID:           gout.UUID,
		Content:           msgContent,
	}
	b, err = marshalLog(t, win)
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
	b, err = marshalLog(t, rin)
	req = httptest.NewRequest(http.MethodPost, "/read", bytes.NewBuffer(b))
	w = httptest.NewRecorder()
	ufo.ReadHandler(w, req)
	resp = w.Result()
	b, err = ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	rout := &ufo.ReadOut{}
	require.Nil(t, unmarshalLog(t, b, rout))
	assert.Equal(t, 1, len(rout.Msgs))
	assert.Equal(t, msgContent, rout.Msgs[0].Content)
}

func TestRegIn(t *testing.T) {
	pub, sig, _ := genKeyPartsRSA(t)
	m := &ufo.RegisterIn{Public: pub, Sig: ufo.Sig(sig)}
	b, err := marshalLog(t, m)
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
		b, err = marshalLog(t, m)
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
		b, err = marshalLog(t, m)
		require.Nil(t, err)
		req := httptest.NewRequest(http.MethodPost, "/reg", bytes.NewBuffer(b))
		ufo.RegisterInHandler(w, req)
		resp := w.Result()
		assert.Equal(t, 400, resp.StatusCode)
	})
}
