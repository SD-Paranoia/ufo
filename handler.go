package ufo

import (
	"log"
	"net/http"
	"sync"
)

type Handler struct {
	*sync.RWMutex
	m map[Page]http.HandlerFunc
}

func MakeHandler() *Handler {
	return &Handler{
		RWMutex: &sync.RWMutex{},
		m:       make(map[Page]http.HandlerFunc),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.RLock()
	defer h.RUnlock()
	p := Page{path: r.URL.Path, method: r.Method}
	if h := h.m[p]; h != nil {
		h(w, r)
		return
	}
	http.NotFoundHandler().ServeHTTP(w, r)
	log.Printf("Unmatched page: %v\n", p)
}

func (h *Handler) Register(handl http.HandlerFunc, pages ...Page) {
	h.Lock()
	for _, p := range pages {
		h.m[p] = handl
	}
	h.Unlock()
}
