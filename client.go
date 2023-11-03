package hkp

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"

	"github.com/ProtonMail/go-crypto/openpgp"
)

type Client struct {
	Host     string
	Insecure bool
}

func (c *Client) hostURL() (*url.URL, error) {
	if u, err := url.Parse(c.Host); err == nil {
		if !c.Insecure && u.Scheme != "https" {
			return nil, fmt.Errorf("hkp: refusing to connect to non-HTTPS keyserver")
		}
		return u, nil
	}

	host := c.Host
	_, addrs, err := net.LookupSRV("hkp", "tcp", host)
	if dnsErr, ok := err.(*net.DNSError); ok {
		if dnsErr.IsTemporary {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(addrs) > 0 {
		addr := addrs[0]
		host = fmt.Sprintf("%v:%v", addr.Target, addr.Port)
	}

	scheme := "https"
	if c.Insecure {
		scheme = "http"
	}

	return &url.URL{Scheme: scheme, Host: host}, nil
}

func (c *Client) url(p string) (*url.URL, error) {
	u, err := c.hostURL()
	if err != nil {
		return nil, err
	}

	u.Path = path.Join(u.Path, p)
	return u, nil
}

func (c *Client) lookup(op string, req *LookupRequest) (*http.Response, error) {
	u, err := c.url(lookupPath)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("op", op)
	q.Set("search", req.Search)
	q.Set("options", req.Options.format())
	if req.Exact {
		q.Set("exact", "on")
	}
	q.Set("fingerprint", "on") // implicit
	u.RawQuery = q.Encode()

	return http.Get(u.String())
}

func (c *Client) Index(req *LookupRequest) ([]IndexKey, error) {
	resp, err := c.lookup("index", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hkp: failed to get index: %v %v", resp.StatusCode, resp.Status)
	}

	return readIndex(resp.Body)
}

func (c *Client) Get(req *LookupRequest) (openpgp.EntityList, error) {
	resp, err := c.lookup("get", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hkp: failed to get key: %v %v", resp.StatusCode, resp.Status)
	}

	return openpgp.ReadArmoredKeyRing(resp.Body)
}

func (c *Client) Add(el openpgp.EntityList) error {
	u, err := c.url(addPath)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	if err := serializeArmoredKeyRing(&b, el); err != nil {
		return err
	}

	v := url.Values{}
	v.Set("keytext", b.String())

	resp, err := http.PostForm(u.String(), v)
	if err != nil {
		return err
	} else if resp.StatusCode/100 != 2 {
		return fmt.Errorf("hkp: failed to add key: %v %v", resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()

	return nil
}
