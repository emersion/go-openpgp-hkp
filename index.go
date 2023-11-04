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

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func primarySelfSignature(e *openpgp.Entity) *packet.Signature {
	var selfSig *packet.Signature
	for _, ident := range e.Identities {
		if selfSig == nil {
			selfSig = ident.SelfSignature
		} else if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
			return ident.SelfSignature
		}
	}
	return selfSig
}

func signatureExpirationTime(sig *packet.Signature) time.Time {
	if sig.KeyLifetimeSecs == nil {
		return time.Time{}
	}
	dur := time.Duration(*sig.KeyLifetimeSecs) * time.Second
	return sig.CreationTime.Add(dur)
}

const indexVersion = 1

type IndexFlags int

const (
	IndexKeyRevoked IndexFlags = 1 << iota
	IndexKeyDisabled
	IndexKeyExpired
)

func parseIndexFlags(s string) (IndexFlags, error) {
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

func (flags IndexFlags) format() string {
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
	CreationTime   time.Time
	ExpirationTime time.Time
	Algo           packet.PublicKeyAlgorithm
	Fingerprint    []byte
	BitLength      int
	Flags          IndexFlags
	Identities     []IndexIdentity
}

type IndexIdentity struct {
	Name           string
	CreationTime   time.Time
	ExpirationTime time.Time
	Flags          IndexFlags
}

// IndexKeyFromEntity creates an IndexKey from an openpgp.Entity.
func IndexKeyFromEntity(e *openpgp.Entity) (*IndexKey, error) {
	key := e.PrimaryKey
	sig := primarySelfSignature(e)

	bitLen, err := key.BitLength()
	if err != nil {
		return nil, err
	}

	idents := make([]IndexIdentity, 0, len(e.Identities))
	for _, ident := range e.Identities {
		idents = append(idents, IndexIdentity{
			Name:           ident.Name,
			CreationTime:   ident.SelfSignature.CreationTime,
			ExpirationTime: signatureExpirationTime(ident.SelfSignature),
		})
	}

	return &IndexKey{
		CreationTime:   key.CreationTime,
		ExpirationTime: signatureExpirationTime(sig),
		Algo:           key.PubKeyAlgo,
		Fingerprint:    key.Fingerprint,
		BitLength:      int(bitLen),
		Identities:     idents,
	}, nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return fmt.Sprintf("%d", t.Unix())
}

// writeIndex writes a machine-readable key index to w.
func writeIndex(w io.Writer, keys []IndexKey) error {
	_, err := fmt.Fprintf(w, "info:%d:%d\n", indexVersion, len(keys))
	if err != nil {
		return err
	}

	for _, key := range keys {
		_, err = fmt.Fprintf(w, "pub:%X:%d:%d:%s:%s:%s\n",
			key.Fingerprint[:], key.Algo, key.BitLength,
			formatTime(key.CreationTime), formatTime(key.ExpirationTime),
			key.Flags.format())
		if err != nil {
			return err
		}

		for _, ident := range key.Identities {
			name := url.PathEscape(ident.Name)
			_, err = fmt.Fprintf(w, "uid:%s:%s:%s:%s\n",
				name, formatTime(ident.CreationTime),
				formatTime(ident.ExpirationTime), ident.Flags.format())
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	sec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0), nil
}

func readIndex(r io.Reader) ([]IndexKey, error) {
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
			fingerprint := make([]byte, 20)
			copy(fingerprint[:], fingerprintSlice)

			algo, err := strconv.Atoi(fields[2])
			if err != nil {
				return keys, err
			}
			bitLen, err := strconv.Atoi(fields[3])
			if err != nil {
				return keys, err
			}
			creationTime, err := parseTime(fields[4])
			if err != nil {
				return keys, err
			}
			expirationTime, err := parseTime(fields[5])
			if err != nil {
				return keys, err
			}
			flags, err := parseIndexFlags(fields[6])
			if err != nil {
				return keys, err
			}

			keys = append(keys, IndexKey{
				CreationTime:   creationTime,
				ExpirationTime: expirationTime,
				Algo:           packet.PublicKeyAlgorithm(algo),
				Fingerprint:    fingerprint,
				BitLength:      bitLen,
				Flags:          flags,
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
			creationTime, err := parseTime(fields[2])
			if err != nil {
				return keys, err
			}
			expirationTime, err := parseTime(fields[3])
			if err != nil {
				return keys, err
			}
			flags, err := parseIndexFlags(fields[4])
			if err != nil {
				return keys, err
			}

			lastKey := &keys[len(keys)-1]
			lastKey.Identities = append(lastKey.Identities, IndexIdentity{
				Name:           name,
				CreationTime:   creationTime,
				ExpirationTime: expirationTime,
				Flags:          flags,
			})
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
