// Package hkp implements OpenPGP HTTP Keyserver Protocol (HKP), as defined in
// https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
package hkp

import (
	"strings"
)

// Base is the base path for the HTTP API.
const Base = "/pks"

const (
	lookupPath = Base + "/lookup"
	addPath = Base + "/add"
)

type LookupOptions struct {
	NoModification bool
}

func (opts *LookupOptions) format() string {
	var l []string
	l = append(l, "mr") // implicit
	if opts.NoModification {
		l = append(l, "nm")
	}
	return strings.Join(l, ",")
}

func parseLookupOptions(s string) *LookupOptions {
	var opts LookupOptions
	for _, opt := range strings.Split(s, ",") {
		switch opt {
		case "nm":
			opts.NoModification = true
		}
	}
	return &opts
}

type LookupRequest struct {
	Search string
	Options LookupOptions
	Exact bool
}
