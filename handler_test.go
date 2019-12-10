package ufo_test

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SD-Paranoia/ufo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testServer(hs http.HandlerFunc, p ufo.Page) *httptest.Server {
	handl := ufo.MakeHandler()
	handl.Register(hs, p)
	return httptest.NewServer(handl)
}

func genBasicHandler(s string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(s))
	}
}

func TestServe(t *testing.T) {
	const expect = "Hello World\n"
	srv := testServer(genBasicHandler(expect), ufo.Page{"/hello", http.MethodGet})
	c := srv.Client()
	resp, err := c.Get(srv.URL + "/hello")
	require.Nil(t, err)
	b, err := ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	assert.Equal(t, expect, string(b))
	t.Run("not found", func(t *testing.T) {
		resp, err := c.Get(srv.URL)
		require.Nil(t, err)
		require.Equal(t, 404, resp.StatusCode)
	})
}
