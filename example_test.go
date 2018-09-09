package hkp_test

import (
	"log"

	"github.com/emersion/go-openpgp-hkp"
)

func ExampleClient() {
	c := hkp.Client{Host: "https://pgp.mit.edu"}

	req := hkp.LookupRequest{Search: "0x2C6464AF2A8E4C02"}
	index, err := c.Index(&req)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(index)

	keys, err := c.Get(&req)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(keys)
}
