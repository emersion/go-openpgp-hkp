package hkp

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var (
	ErrNotFound = errors.New("hkp: not found")
	ErrForbidden = errors.New("hkp: forbidden")
)

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
	Adder Adder
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
		if err != nil {
			httpError(w, err)
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
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if err := WriteIndex(w, res); err != nil {
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

	mr, err := r.MultipartReader()
	if err != nil {
		httpError(w, err)
		return
	}

	var el openpgp.EntityList
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			httpError(w, err)
			return
		}

		if p.FormName() == "keytext" {
			el, err = openpgp.ReadArmoredKeyRing(p)
			if err != nil {
				httpError(w, err)
				return
			}
			break
		}
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
