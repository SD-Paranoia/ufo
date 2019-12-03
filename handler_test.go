package ufo

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testServer(hs http.HandlerFunc, p Page) *httptest.Server {
	handl := MakeHandler()
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
	srv := testServer(genBasicHandler(expect), Page{"/", http.MethodGet})
	c := srv.Client()
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != expect {
		t.Fatal("content mismatch")
	}
}