package hkp

import (
	"encoding/hex"
	"fmt"
	"time"
	"io"
	"net/url"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

const indexVersion = 1

type IndexFlags int

const (
	IndexKeyRevoked IndexFlags = 1 << iota
	IndexKeyDisabled
	IndexKeyExpired
)

func (flags IndexFlags) String() string {
	var res []rune
	if flags & IndexKeyRevoked != 0 {
		res = append(res, 'r')
	}
	if flags & IndexKeyDisabled != 0 {
		res = append(res, 'd')
	}
	if flags & IndexKeyExpired != 0 {
		res = append(res, 'e')
	}
	return string(res)
}

type IndexKey struct {
	CreationTime time.Time
	Algo packet.PublicKeyAlgorithm
	Fingerprint [20]byte
	BitLength int
	Flags IndexFlags
	Identities []IndexIdentity
}

type IndexIdentity struct {
	Name string
	CreationTime time.Time
	Flags IndexFlags
}

// IndexKeyFromEntity creates an IndexKey from an openpgp.Entity.
func IndexKeyFromEntity(e *openpgp.Entity) (*IndexKey, error) {
	key := e.PrimaryKey

	bitLen, err := key.BitLength()
	if err != nil {
		return nil, err
	}

	idents := make([]IndexIdentity, 0, len(e.Identities))
	for _, ident := range e.Identities {
		idents = append(idents, IndexIdentity{
			Name: ident.Name,
			CreationTime: ident.SelfSignature.CreationTime,
		})
	}

	return &IndexKey{
		CreationTime: key.CreationTime,
		Algo: key.PubKeyAlgo,
		Fingerprint: key.Fingerprint,
		BitLength: int(bitLen),
		Identities: idents,
	}, nil
}

// WriteIndex writes a machine-readable key index to w.
func WriteIndex(w io.Writer, keys []IndexKey) error {
	_, err := fmt.Fprintf(w, "info:%d:%d\n", indexVersion, len(keys))
	if err != nil {
		return err
	}

	for _, key := range keys {
		fingerprint := hex.EncodeToString(key.Fingerprint[:])
		// TODO: expiration time, if any
		_, err = fmt.Fprintf(w, "pub:%s:%d:%d:%d:%s:%s\n",
			fingerprint, key.Algo, key.BitLength, key.CreationTime.Unix(),
			"", key.Flags.String())
		if err != nil {
			return err
		}

		for _, ident := range key.Identities {
			name := url.PathEscape(ident.Name)
			// TODO: expiration time, if any
			_, err = fmt.Fprintf(w, "uid:%s:%d:%s:%s\n",
				name, ident.CreationTime.Unix(), "", ident.Flags.String())
			if err != nil {
				return err
			}
		}
	}

	return nil
}
