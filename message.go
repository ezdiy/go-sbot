package ssb

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	//"github.com/go-kit/kit/log"
)

type SignedMessage struct {
	Message
	Signature Signature `json:"signature"`
}

type Message struct {
	Previous  *Ref            `json:"previous"`
	Author    Ref             `json:"author"`
	Sequence  int             `json:"sequence"`
	Timestamp float64         `json:"timestamp"`
	Hash      string          `json:"hash"`
	Content   json.RawMessage `json:"content"`
}

func Encode(i interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(i)
	if err != nil {
		return nil, err
	}
	return bytes.Trim(buf.Bytes(), "\n"), nil
}

func (m *SignedMessage) Verify(latest *SignedMessage) int {
	if latest == nil && m.Sequence == 1 {
		return 0
	}
	if m.Previous == nil && latest == nil {
		return 0
	}
	if m.Sequence != latest.Sequence+1 || m.Timestamp <= latest.Timestamp {
		//l.Log("verifyerror", "sequence", "seq", m.Sequence, "ts", m.Timestamp, "prev", m.Previous)
		return -1
	}
	if m.Previous == nil && latest != nil {
		//l.Log("verifyerror", "malformed", "seq", m.Sequence, "ts", m.Timestamp, "prev", m.Previous)
		return -2
	}
	if *m.Previous != latest.Key() {
		//l.Log("verifyerror", "fork", "seq", m.Sequence, "ts", m.Timestamp, "prev", m.Previous)
		return -3
	}
	return 0
}

func (m *SignedMessage) VerifySignature() error {
	buf, err := Encode(m.Message)
	if err != nil {
		return nil
	}
	err = m.Signature.Verify(buf, m.Author)
	if err != nil {
		return err
	}
	return nil
}

func (m *SignedMessage) Same(x *SignedMessage) bool {
	if m == nil {
		return x == m
	} else {
		return m.Sequence == x.Sequence
	}
}

func (m *SignedMessage) Encode() []byte {
	buf, _ := Encode(m)
	return buf
}

func (m *SignedMessage) Key() Ref {
	if m == nil {
		return Ref{}
	}
	buf, _ := Encode(m)
	/*enc := RemoveUnsupported(charmap.ISO8859_1.NewEncoder())
	buf, err := enc.Bytes(buf)
	if err != nil {
		panic(err)
	}*/
	buf = ToJSBinary(buf)
	switch strings.ToLower(m.Hash) {
	case "sha256":
		hash := sha256.Sum256(buf)
		ref, _ := NewRef(RefMessage, hash[:], RefAlgoSha256)
		return ref
	}
	return Ref{}
}

func (m *Message) Sign(s Signer) *SignedMessage {
	content, _ := Encode(m)
	sig := s.Sign(content)
	return &SignedMessage{Message: *m, Signature: sig}
}
