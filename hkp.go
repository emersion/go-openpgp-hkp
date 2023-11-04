// Package hkp implements OpenPGP HTTP Keyserver Protocol (HKP), as defined in
// https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
package hkp

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// Base is the base path for the HTTP API.
const Base = "/pks"

const (
	lookupPath = Base + "/lookup"
	addPath    = Base + "/add"
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
	Search  string
	Options LookupOptions
	Exact   bool
}

func serializeArmoredKeyRing(w io.Writer, el openpgp.EntityList) error {
	aw, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	defer aw.Close()

	for _, e := range el {
		if err := e.Serialize(aw); err != nil {
			return err
		}
	}

	return nil
}

type KeyIDSearch []byte

// ParseKeyIDSearch parses a key ID search prefixed with "0x". If the supplied
// search isn't a key ID, returns nil.
func ParseKeyIDSearch(search string) KeyIDSearch {
	if !strings.HasPrefix(search, "0x") {
		return nil
	}
	b, err := hex.DecodeString(search[2:])
	if err != nil {
		return nil
	}
	switch len(b) {
	case 20, 8, 4:
		return KeyIDSearch(b)
	default:
		return nil
	}
}

// Fingerprint extracts a fingerprint from a key ID search. It returns nil if
// the search doesn't contain a fingerprint.
func (search KeyIDSearch) Fingerprint() *[]byte {
	if len(search) != 20 {
		return nil
	}
	b := make([]byte, 20)
	copy(b[:], search)
	return &b
}

// KeyId extracts a 64-bit key ID from a key ID search. It returns nil if the
// search doesn't contain a 64-bit key ID.
func (search KeyIDSearch) KeyId() *uint64 {
	var b []byte
	switch len(search) {
	case 20:
		b = search[12:20]
	case 8:
		b = search
	default:
		return nil
	}
	keyID := binary.BigEndian.Uint64(b)
	return &keyID
}

// KeyIdShort extracts a 32-bit key ID from a key ID search. It returns nil if
// the search doesn't contain a 32-bit key ID.
func (search KeyIDSearch) KeyIdShort() *uint32 {
	var b []byte
	switch len(search) {
	case 20:
		b = search[16:20]
	case 8:
		b = search[4:8]
	case 4:
		b = search
	default:
		return nil
	}
	keyID := binary.BigEndian.Uint32(b)
	return &keyID
}
