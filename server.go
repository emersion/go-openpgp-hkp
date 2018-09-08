package hkp

import (
	"errors"
	"net/http"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var ErrNotFound = errors.New("hkp: not found")

type LookupOptions struct {
	NoModification bool
}

type LookupRequest struct {
	Search string
	Options LookupOptions
	Exact bool
}

type Lookuper interface {
	Get(req *LookupRequest) (*openpgp.Entity, error)
	Index(req *LookupRequest) ([]IndexKey, error)
}

type Handler struct {
	Lookuper Lookuper
}

func (h *Handler) serveLookup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	op := q.Get("op")

	optionsList := strings.Split(q.Get("options"), ",")
	options := make(map[string]bool)
	for _, opt := range optionsList {
		options[opt] = true
	}

	req := LookupRequest{
		Search: q.Get("search"),
		Options: LookupOptions{
			NoModification: options["nm"],
		},
		Exact: q.Get("exact") == "on",
	}

	switch op {
	case "get":
		e, err := h.Lookuper.Get(&req)
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
	case "index", "vindex":
		res, err := h.Lookuper.Index(&req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if err := WriteIndex(w, res); err != nil {
			panic(err)
		}
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
