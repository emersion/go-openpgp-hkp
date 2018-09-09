package hkp

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

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

func ParseIndexFlags(s string) (IndexFlags, error) {
	var res IndexFlags
	for _, r := range []rune(s) {
		switch r {
		case 'r':
			res |= IndexKeyRevoked
		case 'd':
			res |= IndexKeyDisabled
		case 'e':
			res |= IndexKeyExpired
		}
	}
	return res, nil
}

func (flags IndexFlags) String() string {
	var res []rune
	if flags&IndexKeyRevoked != 0 {
		res = append(res, 'r')
	}
	if flags&IndexKeyDisabled != 0 {
		res = append(res, 'd')
	}
	if flags&IndexKeyExpired != 0 {
		res = append(res, 'e')
	}
	return string(res)
}

type IndexKey struct {
	CreationTime time.Time
	Algo         packet.PublicKeyAlgorithm
	Fingerprint  [20]byte
	BitLength    int
	Flags        IndexFlags
	Identities   []IndexIdentity
}

type IndexIdentity struct {
	Name         string
	CreationTime time.Time
	Flags        IndexFlags
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
			Name:         ident.Name,
			CreationTime: ident.SelfSignature.CreationTime,
		})
	}

	return &IndexKey{
		CreationTime: key.CreationTime,
		Algo:         key.PubKeyAlgo,
		Fingerprint:  key.Fingerprint,
		BitLength:    int(bitLen),
		Identities:   idents,
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

func ReadIndex(r io.Reader) ([]IndexKey, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("hkp: unexpected EOF")
	}
	fields := strings.SplitN(scanner.Text(), ":", 3)
	if len(fields) != 3 || fields[0] != "info" {
		return nil, errors.New("hkp: failed to parse info")
	}
	ver, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil, err
	}
	if ver != indexVersion {
		return nil, errors.New("hkp: unsupported index version")
	}

	var keys []IndexKey
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}

		fields := strings.Split(scanner.Text(), ":")
		switch fields[0] {
		case "pub":
			if len(fields) != 7 {
				return keys, errors.New("hkp: failed to parse pub")
			}

			fingerprintSlice, err := hex.DecodeString(fields[1])
			if err != nil {
				return keys, err
			}
			if len(fingerprintSlice) != 20 {
				return keys, errors.New("hkp: invalid fingerprint size")
			}
			var fingerprint [20]byte
			copy(fingerprint[:], fingerprintSlice)

			algo, err := strconv.Atoi(fields[2])
			if err != nil {
				return keys, err
			}
			bitLen, err := strconv.Atoi(fields[3])
			if err != nil {
				return keys, err
			}
			creationTime, err := strconv.ParseInt(fields[4], 10, 64)
			if err != nil {
				return keys, err
			}
			flags, err := ParseIndexFlags(fields[6])
			if err != nil {
				return keys, err
			}

			keys = append(keys, IndexKey{
				CreationTime: time.Unix(creationTime, 0),
				Algo:         packet.PublicKeyAlgorithm(algo),
				Fingerprint:  fingerprint,
				BitLength:    bitLen,
				Flags:        flags,
			})
		case "uid":
			if len(keys) == 0 {
				return keys, errors.New("hkp: got uid before pub")
			}
			if len(fields) != 5 {
				return keys, errors.New("hkp: failed to parse uid")
			}

			name, err := url.PathUnescape(fields[1])
			if err != nil {
				return keys, err
			}
			creationTime, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				return keys, err
			}
			flags, err := ParseIndexFlags(fields[4])
			if err != nil {
				return keys, err
			}

			lastKey := &keys[len(keys)-1]
			lastKey.Identities = append(lastKey.Identities, IndexIdentity{
				Name:         name,
				CreationTime: time.Unix(creationTime, 0),
				Flags:        flags,
			})
		default:
			return keys, errors.New("hkp: invalid index line type")
		}
	}

	if err := scanner.Err(); err != nil {
		return keys, err
	}
	if len(keys) != n {
		return keys, errors.New("hkp: key count mismatch")
	}
	return keys, nil
}
