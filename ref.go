package ssb

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/ed25519"
)

type Ref string

type RefType int

const (
	RefInvalid RefType = iota
	RefFeed
	RefMessage
	RefBlob
)

type RefAlgo int

const (
	RefAlgoInvalid RefAlgo = iota
	RefAlgoSha256
	RefAlgoEd25519
)

var (
	ErrInvalidRefAlgo = errors.New("Invalid Ref Algo")
	ErrInvalidSig     = errors.New("Invalid Signature")
	ErrInvalidHash    = errors.New("Invalid Hash")
)

func (r Ref) Type() RefType {
	switch r[0] {
	case '@':
		return RefFeed
	case '%':
		return RefMessage
	case '&':
		return RefBlob
	}
	return RefInvalid
}

func (r Ref) Algo() RefAlgo {
	parts := strings.Split(string(r), ".")
	if len(parts) != 2 {
		return RefAlgoInvalid
	}
	switch strings.ToLower(parts[1]) {
	case "ed25519":
		return RefAlgoEd25519
	case "sha256":
		return RefAlgoSha256
	}
	return RefAlgoInvalid
}

func (r Ref) Raw() string {
	return strings.Split(strings.TrimLeft(string(r), "@%&"), ".")[0]
}

func (r Ref) CheckHash(content []byte) error {
	switch r.Algo() {
	case RefAlgoSha256:
		rawhash, err := base64.StdEncoding.DecodeString(r.Raw())
		if err != nil {
			return err
		}
		contentHash := sha256.Sum256(content)
		if bytes.Equal(rawhash, contentHash[:]) {
			return nil
		}
		return ErrInvalidHash
	}
	return ErrInvalidHash
}

type Signature string

type SigAlgo int

const (
	SigAlgoInvalid SigAlgo = iota
	SigAlgoEd25519
)

func (s Signature) Algo() SigAlgo {
	parts := strings.Split(string(s), ".")
	if len(parts) != 3 || parts[1] != "sig" {
		return SigAlgoInvalid
	}
	switch strings.ToLower(parts[2]) {
	case "ed25519":
		return SigAlgoEd25519
	}
	return SigAlgoInvalid
}

func (s Signature) Raw() string {
	return strings.Split(string(s), ".")[0]
}

func (s Signature) Verify(content []byte, r Ref) error {
	switch s.Algo() {
	case SigAlgoEd25519:
		rawsig, err := base64.StdEncoding.DecodeString(s.Raw())
		if err != nil {
			return err
		}
		if r.Algo() != RefAlgoEd25519 {
			return ErrInvalidSig
		}
		rawkey, err := base64.StdEncoding.DecodeString(r.Raw())
		if err != nil {
			return err
		}
		key := ed25519.PublicKey(rawkey)
		if ed25519.Verify(key, content, rawsig) {
			return nil
		}
		return ErrInvalidSig
	}
	return ErrInvalidSig
}