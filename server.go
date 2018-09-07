package hkp

import (
	"errors"
	"net/http"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var ErrNotFound = errors.New("hkp: not found")

type LookupRequest struct {}

type Lookuper interface {
	Get(search string) (*openpgp.Entity, error)
	Index(search string) ([]IndexKey, error)
}

type Handler struct {
	Lookuper Lookuper
}

func (h *Handler) serveLookup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	op := q.Get("op")
	search := q.Get("search")
	// options := q.Get("options") // TODO

	switch op {
	case "get":
		e, err := h.Lookuper.Get(search)
		if err == ErrNotFound {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pgp-keys")
		aw, err := armor.Encode(w, "PGP PUBLIC KEY BLOCK", nil)
		if err != nil {
			panic(err)
		}
		defer aw.Close()
		if err := e.Serialize(aw); err != nil {
			panic(err)
		}
	case "index":
		res, err := h.Lookuper.Index(search)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if err := WriteIndex(w, res); err != nil {
			panic(err)
		}
	case "vindex":
	default:
		http.Error(w, "501 Not Implemented", http.StatusNotImplemented)
	}
}

func (h *Handler) serveAdd(w http.ResponseWriter, r *http.Request) {
	// TODO
	http.Error(w, "501 Not Implemented", http.StatusNotImplemented)
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case lookupPath:
		h.serveLookup(w, r)
	case addPath:
		h.serveAdd(w, r)
	}
}
