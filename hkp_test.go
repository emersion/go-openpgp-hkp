package hkp_test

import (
	"bytes"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	hkp "github.com/emersion/go-openpgp-hkp"
)

var stallmanPubkey openpgp.EntityList

func init() {
	var err error
	stallmanPubkey, err = openpgp.ReadArmoredKeyRing(strings.NewReader(stallmanPubkeyStr))
	if err != nil {
		panic(err)
	}
}

type mockBackend struct {
	added openpgp.EntityList
}

func (mb *mockBackend) Get(req *hkp.LookupRequest) (openpgp.EntityList, error) {
	if req.Search != "stallman" {
		return nil, nil
	}
	return stallmanPubkey, nil
}

func (mb *mockBackend) Index(req *hkp.LookupRequest) ([]hkp.IndexKey, error) {
	if req.Search != "stallman" {
		return nil, nil
	}

	keys := make([]hkp.IndexKey, len(stallmanPubkey))
	for i, e := range stallmanPubkey {
		key, err := hkp.IndexKeyFromEntity(e)
		if err != nil {
			return nil, err
		}
		keys[i] = *key
	}
	return keys, nil
}

func (mb *mockBackend) Add(keys openpgp.EntityList) error {
	mb.added = append(mb.added, keys...)
	return nil
}

func Test_index(t *testing.T) {
	h := hkp.Handler{Lookuper: &mockBackend{}}
	ts := httptest.NewServer(&h)
	defer ts.Close()

	c := hkp.Client{Host: ts.URL, Insecure: true}

	req := hkp.LookupRequest{Search: "stallman"}
	index, err := c.Index(&req)
	if err != nil {
		t.Fatalf("Client.Index(): %v", err)
	}

	creationTime, _ := time.Parse(time.RFC3339, "2013-07-20T18:32:38+02:00")
	key := hkp.IndexKey{
		CreationTime: creationTime.Local(),
		Algo:         1,
		Fingerprint:  stallmanPubkey[0].PrimaryKey.Fingerprint,
		BitLength:    4096,
		Flags:        0,
		Identities: []hkp.IndexIdentity{
			{
				Name:         "Richard Stallman <rms@gnu.org>",
				CreationTime: creationTime.Local(),
				Flags:        0,
			},
		},
	}

	if len(index) != 1 {
		t.Errorf("Client.Index: got %v results, want 1", len(index))
	} else if !reflect.DeepEqual(index[0], key) {
		t.Errorf("Client.Index: got %+v, want %+v", index[0], key)
	}
}

func Test_get(t *testing.T) {
	h := hkp.Handler{Lookuper: &mockBackend{}}
	ts := httptest.NewServer(&h)
	defer ts.Close()

	c := hkp.Client{Host: ts.URL, Insecure: true}

	req := hkp.LookupRequest{Search: "stallman"}
	keys, err := c.Get(&req)
	if err != nil {
		t.Fatalf("Client.Get(): %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("Client.Get: got %v key, want 1", len(keys))
	} else if !bytes.Equal(keys[0].PrimaryKey.Fingerprint[:], stallmanPubkey[0].PrimaryKey.Fingerprint[:]) {
		t.Errorf("Client.Get: got %+v, want %+v", keys[0], stallmanPubkey[0])
	}
}

func Test_add(t *testing.T) {
	mb := mockBackend{}
	h := hkp.Handler{Adder: &mb}
	ts := httptest.NewServer(&h)
	defer ts.Close()

	c := hkp.Client{Host: ts.URL, Insecure: true}

	if err := c.Add(stallmanPubkey); err != nil {
		t.Fatalf("Client.Add(): %v", err)
	}

	if len(mb.added) != 1 {
		t.Errorf("want 1 key added, got %v", len(mb.added))
	}
}

func TestKeyIDSearch(t *testing.T) {
	shortKeyIDSearch := hkp.ParseKeyIDSearch("0x2A8E4C02")
	if id := shortKeyIDSearch.KeyIdShort(); id == nil {
		t.Errorf("short.KeyIdShort() = nil, want non-nil")
	} else if *id != 0x2A8E4C02 {
		t.Errorf("short.KeyIdShort() = 0x%X, want 0x%X", *id, 0x2A8E4C02)
	}
	if fingerprint := shortKeyIDSearch.Fingerprint(); fingerprint != nil {
		t.Errorf("short.Fingerprint() = %v, want nil", fingerprint)
	}

	fingerprintIDSearch := hkp.ParseKeyIDSearch("0x67819B343B2AB70DED9320872C6464AF2A8E4C02")
	if id := fingerprintIDSearch.KeyId(); id == nil {
		t.Errorf("fingerprint.KeyId() = nil, want non-nil")
	} else if *id != 0x2C6464AF2A8E4C02 {
		t.Errorf("fingerprint.KeyId() = 0x%X, want 0x%X", id, 0x2C6464AF2A8E4C02)
	}
	if fingerprint := fingerprintIDSearch.Fingerprint(); fingerprint == nil {
		t.Errorf("fingerprint.Fingerprint() = nil, want non-nil")
	} else if !bytes.Equal((fingerprint)[:], stallmanPubkey[0].PrimaryKey.Fingerprint[:]) {
		t.Errorf("fingerprint.Fingerprint() = %v, want %v", fingerprint, stallmanPubkey[0].PrimaryKey.Fingerprint)
	}
}

const stallmanPubkeyStr = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.10 (GNU/Linux)

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
cy1evijaNWDCCGd/gd9jqc1VFW6Klq0=
=Fhj2
-----END PGP PUBLIC KEY BLOCK-----
`
