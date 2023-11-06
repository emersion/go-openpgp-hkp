package hkp

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

var (
	ErrNotFound  = errors.New("hkp: not found")
	ErrForbidden = errors.New("hkp: forbidden")
)

type Lookuper interface {
	Get(req *LookupRequest) (openpgp.EntityList, error)
	Index(req *LookupRequest) ([]IndexKey, error)
}

type Adder interface {
	Add(el openpgp.EntityList) error
}

func httpError(w http.ResponseWriter, err error) {
	switch err {
	case ErrNotFound:
		http.NotFound(w, nil)
	case ErrForbidden:
		http.Error(w, err.Error(), http.StatusForbidden)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type Handler struct {
	Lookuper Lookuper
	Adder    Adder
}

func (h *Handler) serveLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.Lookuper == nil {
		http.Error(w, "Not Implemented", http.StatusNotImplemented)
		return
	}

	q := r.URL.Query()

	req := LookupRequest{
		Search:  q.Get("search"),
		Options: *parseLookupOptions(q.Get("options")),
		Exact:   q.Get("exact") == "on",
	}

	switch q.Get("op") {
	case "get":
		el, err := h.Lookuper.Get(&req)
		if err != nil {
			httpError(w, err)
			return
		} else if len(el) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pgp-keys")
		if err := serializeArmoredKeyRing(w, el); err != nil {
			panic(err)
		}
	case "index", "vindex":
		res, err := h.Lookuper.Index(&req)
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if err := writeIndex(w, res); err != nil {
			panic(err)
		}
	default:
		http.Error(w, "Not Implemented", http.StatusNotImplemented)
	}
}

func (h *Handler) serveAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.Adder == nil {
		http.Error(w, "Not Implemented", http.StatusNotImplemented)
		return
	}

	if err := r.ParseForm(); err != nil {
		httpError(w, err)
		return
	}

	s := r.FormValue("keytext")
	if s == "" {
		return
	}

	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(s))
	if err != nil {
		httpError(w, err)
		return
	}

	r.Body.Close()

	if err := h.Adder.Add(el); err != nil {
		httpError(w, err)
		return
	}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case lookupPath:
		h.serveLookup(w, r)
	case addPath:
		h.serveAdd(w, r)
	default:
		http.Error(w, "Not Implemented", http.StatusNotImplemented)
	}
}
