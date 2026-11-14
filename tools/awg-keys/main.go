// Generate or derive WireGuard keys with Go's standard X25519 implementation.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"
)

type result struct {
	PublicKey  string
	PrivateKey string `json:",omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	curve := ecdh.X25519()
	var key *ecdh.PrivateKey
	var err error
	switch os.Args[1] {
	case "new":
		key, err = curve.GenerateKey(rand.Reader)
	case "public":
		input, readErr := io.ReadAll(io.LimitReader(os.Stdin, 128))
		if readErr != nil {
			os.Exit(2)
		}
		raw, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(input)))
		if decodeErr != nil {
			os.Exit(2)
		}
		key, err = curve.NewPrivateKey(raw)
	default:
		os.Exit(2)
	}
	if err != nil {
		os.Exit(2)
	}
	answer := result{PublicKey: base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())}
	if os.Args[1] == "new" {
		answer.PrivateKey = base64.StdEncoding.EncodeToString(key.Bytes())
	}
	if json.NewEncoder(os.Stdout).Encode(answer) != nil {
		os.Exit(2)
	}
}
