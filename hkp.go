// Package hkp implements OpenPGP HTTP Keyserver Protocol (HKP), as defined in
// https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
package hkp

// Base is the base path for the HTTP API.
const Base = "/pks"

const (
	lookupPath = Base + "/lookup"
	addPath = Base + "/add"
)
