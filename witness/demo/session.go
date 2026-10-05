package demo

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bigblue-r4/sgail-playground/witness/internal/merkle"
	"github.com/bigblue-r4/sgail-playground/witness/internal/signer"
	"github.com/bigblue-r4/sgail-playground/witness/internal/store"
)

// FarmNight is the log the page starts from: one night in house 3, as the
// farm feed records it (source "farm", events named as in docs/farm-events.md).
// Someone lowers the minimum ventilation remotely, the house overheats, and a
// crew member puts it back. The question is whether that record can be changed.
var FarmNight = []struct {
	At, Level, Event string
	Data             string
}{
	{"21:00", "INFO", "farm_heartbeat", `{"source":"house-3/controller","kind":"heartbeat"}`},
	{"21:01", "INFO", "farm_reading:ammonia_ppm", `{"source":"house-3/controller","kind":"reading","metric":"ammonia_ppm","value":18.5,"unit":"ppm"}`},
	{"21:02", "INFO", "farm_setting_change:min_ventilation_pct", `{"source":"house-3/controller","kind":"setting_change","setting":"min_ventilation_pct","from":30,"to":10,"by":"remote:jdoe"}`},
	{"21:15", "INFO", "farm_reading:temperature", `{"source":"house-3/controller","kind":"reading","metric":"temperature","value":84.2,"unit":"F"}`},
	{"21:40", "WARN", "farm_alarm:high_temperature", `{"source":"house-3/controller","kind":"alarm","alarm":"high_temperature","severity":"critical","value":92.1,"unit":"F"}`},
	{"21:43", "INFO", "farm_access:house-3/entry", `{"source":"house-3/entry-door","kind":"access","door":"house-3/entry","person":"badge:1042","direction":"in"}`},
	{"21:50", "INFO", "farm_setting_change:min_ventilation_pct", `{"source":"house-3/controller","kind":"setting_change","setting":"min_ventilation_pct","from":10,"to":30,"by":"crew:ana"}`},
	{"22:05", "INFO", "farm_reading:temperature", `{"source":"house-3/controller","kind":"reading","metric":"temperature","value":79.4,"unit":"F"}`},
}

// memSigner is an ed25519 signer held in memory, standing in for the dev or
// hardware key. It satisfies the witness's signer.Signer interface.
type memSigner struct{ priv ed25519.PrivateKey }

func newMemSigner() (*memSigner, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &memSigner{priv}, nil
}

func (m *memSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(m.priv, msg), nil }
func (m *memSigner) PublicKey() ed25519.PublicKey {
	return m.priv.Public().(ed25519.PublicKey)
}

// Session is one visitor's witness: the machine key, the signing key, the log
// as it now stands on the machine, the head file, and the copy of the head a
// transparency mirror holds elsewhere.
type Session struct {
	key     []byte
	signer  signer.Signer
	Entries []store.Entry
	Head    *store.TreeHead // nil: the head file was deleted
	Mirror  store.TreeHead
	trusted *Node // the tree as the witness itself last wrote it
	day     time.Time
}

// NewSession records FarmNight the honest way, one Append at a time, pushing
// each head to the mirror as the witness's drift tick does.
func NewSession() (*Session, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	s, err := newMemSigner()
	if err != nil {
		return nil, err
	}
	ses := &Session{key: key, signer: s, day: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}
	for _, f := range FarmNight {
		at, _ := time.Parse("15:04", f.At)
		e := store.Entry{
			Seq:       uint64(len(ses.Entries) + 1),
			Timestamp: ses.day.Add(time.Duration(at.Hour())*time.Hour + time.Duration(at.Minute())*time.Minute),
			Level:     f.Level,
			Event:     f.Event,
			Source:    "farm",
			Data:      json.RawMessage(f.Data),
		}
		if err := ses.append(e); err != nil {
			return nil, err
		}
	}
	return ses, nil
}

// append is what store.Append does to the tree and head, plus the mirror push.
func (s *Session) append(e store.Entry) error {
	s.Entries = append(s.Entries, e)
	prev := ""
	if s.Head != nil {
		prev = s.Head.Root
	}
	head, err := MakeHead(s.key, s.signer, Leaves(s.Entries), prev, e.Timestamp)
	if err != nil {
		return err
	}
	s.Head = &head
	s.Mirror = head
	s.trusted = Tree(Leaves(s.Entries))
	return nil
}

// ── What an attacker on the machine can do ──────────────────────────────────

// Edit replaces one entry's data, as someone with the machine key could by
// decrypting the record, changing it and encrypting it again.
func (s *Session) Edit(i int, data string) error {
	if i < 0 || i >= len(s.Entries) {
		return fmt.Errorf("no entry %d", i)
	}
	// Compact, not re-encode: re-encoding would sort the keys and change the
	// bytes even when nothing was edited.
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(data)); err != nil {
		return fmt.Errorf("not valid JSON: %w", err)
	}
	s.Entries[i].Data = compact.Bytes()
	return nil
}

// Delete removes one entry from the log file.
func (s *Session) Delete(i int) error {
	if i < 0 || i >= len(s.Entries) {
		return fmt.Errorf("no entry %d", i)
	}
	s.Entries = append(s.Entries[:i:i], s.Entries[i+1:]...)
	return nil
}

// Truncate cuts the last n entries off the log file.
func (s *Session) Truncate(n int) {
	if n > len(s.Entries) {
		n = len(s.Entries)
	}
	s.Entries = s.Entries[:len(s.Entries)-n]
}

// DeleteHead removes the head file.
func (s *Session) DeleteHead() { s.Head = nil }

// Resign is the full cover-up: someone with complete control of the machine
// uses its key and signer to write a fresh, valid head for the altered log.
// The head is signed on the same machine, so this succeeds; only a copy of the
// head kept somewhere else can show the history changed.
func (s *Session) Resign() error {
	prev := ""
	if s.Head != nil {
		prev = s.Head.PrevRoot
	}
	head, err := MakeHead(s.key, s.signer, Leaves(s.Entries), prev, s.day.Add(23*time.Hour))
	if err != nil {
		return err
	}
	s.Head = &head
	return nil
}

// ForgeWithOwnKey is a cover-up by someone who has the machine key but not
// the witness's signing key: they sign a fresh head with a key of their own.
// Before kiss-protocol v3.3.2 the witness accepted it, trusting the key named
// in the head; now the head must carry the witness's own signature.
func (s *Session) ForgeWithOwnKey() error {
	own, err := newMemSigner()
	if err != nil {
		return err
	}
	prev := ""
	if s.Head != nil {
		prev = s.Head.PrevRoot
	}
	head, err := MakeHead(s.key, own, Leaves(s.Entries), prev, s.day.Add(23*time.Hour))
	if err != nil {
		return err
	}
	s.Head = &head
	return nil
}

// ── What the page shows ─────────────────────────────────────────────────────

// Check is one verdict, with the witness's own error text when it fails.
type Check struct {
	OK      bool   `json:"ok"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type State struct {
	Entries []store.Entry   `json:"entries"`
	Head    *store.TreeHead `json:"head"`
	Mirror  store.TreeHead  `json:"mirror"`
	Tree    *Node           `json:"tree"`
	Verify  Check           `json:"verify"`
	Audit   Check           `json:"audit"`
}

// State runs both checks the way the witness does: `witness verify` opens the
// store (rebuild the tree, check the head), and `witness audit` cannot even
// open a store that fails that, so it only compares with the mirror after.
func (s *Session) State() State {
	leaves := Leaves(s.Entries)
	st := State{Entries: s.Entries, Head: s.Head, Mirror: s.Mirror, Tree: Tree(leaves)}
	markChanged(st.Tree, s.trusted)

	if err := VerifyHead(s.key, s.signer, s.Head, leaves); err != nil {
		st.Verify = Check{false, "fail", "store: tree head integrity: " + err.Error()}
		st.Audit = Check{false, "fail", "open store: store: tree head integrity: " + err.Error()}
		return st
	}
	st.Verify = Check{true, "ok", fmt.Sprintf("%d entries verified against the signed head", len(leaves))}
	a := Audit(leaves, s.Mirror)
	st.Audit = Check{a.Status != "tamper", a.Status, a.Message}
	return st
}

// ── Tree layout for the diagram ─────────────────────────────────────────────

// Node is one node of the Merkle tree, split exactly as internal/merkle splits
// it (RFC 6962: left subtree holds the largest power of two below n).
type Node struct {
	Hash     string  `json:"hash"`
	Leaf     int     `json:"leaf"` // entry index for a leaf, -1 otherwise
	Changed  bool    `json:"changed"`
	Children []*Node `json:"children,omitempty"`
	raw      [32]byte
}

// Tree builds the diagram tree. Its root always equals merkle.Root(leaves).
func Tree(leaves [][32]byte) *Node {
	if len(leaves) == 0 {
		return nil
	}
	return build(leaves, 0)
}

func build(leaves [][32]byte, offset int) *Node {
	if len(leaves) == 1 {
		return &Node{Hash: hex.EncodeToString(leaves[0][:]), Leaf: offset, raw: leaves[0]}
	}
	k := 1
	for k < len(leaves) {
		k <<= 1
	}
	k >>= 1
	l, r := build(leaves[:k], offset), build(leaves[k:], offset+k)
	h := merkle.HashNode(l.raw, r.raw)
	return &Node{Hash: hex.EncodeToString(h[:]), Leaf: -1, Children: []*Node{l, r}, raw: h}
}

// markChanged flags every node whose hash differs from the node in the same
// place in the tree the witness wrote. Display only.
func markChanged(now, was *Node) {
	if now == nil {
		return
	}
	now.Changed = was == nil || now.raw != was.raw
	for i, c := range now.Children {
		var w *Node
		if was != nil && i < len(was.Children) {
			w = was.Children[i]
		}
		markChanged(c, w)
	}
}
