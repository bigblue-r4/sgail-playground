// Package demo is the witness log, in memory, for the browser page.
//
// The browser has no disk, so the store's file reading and writing is left
// out. Everything that decides whether a log is intact is the witness's own
// code or a line-for-line port of it:
//
//   - Merkle tree hashing: internal/merkle, copied unchanged from kiss-protocol.
//   - Entry and TreeHead types, ErrMissingTreeHead: internal/store, unchanged.
//   - leafHash, treeHeadSigInput, computeMAC, writeTreeHead, verifyTreeHead,
//     keyAccepted: ported from internal/store/store.go with only the file I/O
//     removed (and no trust allowlist: the page has one key).
//   - Audit: the comparison in cmd/witness/audit.go.
//
// port_test.go checks the ports against the real store: it writes logs to
// disk with store.Append, tampers with the files, and requires store.Open and
// this package to reach the same verdict with the same error.
//
// Not shown here: encryption at rest. The real log is AES-256-GCM encrypted;
// this page shows the integrity checks, which run on the decrypted entries.
package demo

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"lukechampine.com/blake3"

	"github.com/bigblue-r4/sgail-playground/witness/internal/merkle"
	"github.com/bigblue-r4/sgail-playground/witness/internal/signer"
	"github.com/bigblue-r4/sgail-playground/witness/internal/store"
)

// ── Ports from internal/store/store.go ──────────────────────────────────────

// LeafHash is store.leafHash.
func LeafHash(e store.Entry) [32]byte {
	b, _ := json.Marshal(e)
	return merkle.HashLeaf(b)
}

// Leaves hashes every entry, as store.Open does when it rebuilds the tree.
func Leaves(entries []store.Entry) [][32]byte {
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		leaves[i] = LeafHash(e)
	}
	return leaves
}

// sigInput is store.treeHeadSigInput.
func sigInput(size uint64, root [32]byte) []byte {
	var sizeBuf [8]byte
	binary.BigEndian.PutUint64(sizeBuf[:], size)
	input := make([]byte, 8+32)
	copy(input[:8], sizeBuf[:])
	copy(input[8:], root[:])
	return input
}

// computeMAC is store.computeMAC.
func computeMAC(key []byte, size uint64, root [32]byte) [32]byte {
	h := blake3.New(32, key)
	_, _ = h.Write(sigInput(size, root))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MakeHead is store.writeTreeHead without the file write: the head the
// witness would write for these leaves.
func MakeHead(key []byte, s signer.Signer, leaves [][32]byte, prevRoot string, now time.Time) (store.TreeHead, error) {
	root := merkle.Root(leaves)
	mac := computeMAC(key, uint64(len(leaves)), root)
	head := store.TreeHead{
		Size:      uint64(len(leaves)),
		Root:      hex.EncodeToString(root[:]),
		PrevRoot:  prevRoot,
		Timestamp: now.UTC().Format(time.RFC3339),
		MAC:       hex.EncodeToString(mac[:]),
	}
	if s != nil {
		sig, err := s.Sign(sigInput(uint64(len(leaves)), root))
		if err != nil {
			return store.TreeHead{}, fmt.Errorf("sign tree head: %w", err)
		}
		head.Signature = hex.EncodeToString(sig)
		head.SignerKey = hex.EncodeToString(s.PublicKey())
	}
	return head, nil
}

// VerifyHead is store.verifyTreeHead without the file read. A nil head means
// the head file is missing. s is the witness's own signer (nil: a reader with
// no key to pin to); the head's signature must be s's.
func VerifyHead(key []byte, s signer.Signer, head *store.TreeHead, leaves [][32]byte) error {
	if head == nil {
		if len(leaves) == 0 {
			return nil
		}
		return store.ErrMissingTreeHead
	}

	root := merkle.Root(leaves)
	storedRoot, err := hex.DecodeString(head.Root)
	if err != nil || len(storedRoot) != 32 {
		return errors.New("tree head: malformed root")
	}
	var storedRootArr [32]byte
	copy(storedRootArr[:], storedRoot)
	if root != storedRootArr {
		return fmt.Errorf("tree head root mismatch: log tampered (stored %s, computed %s)",
			head.Root, hex.EncodeToString(root[:]))
	}
	if head.Size != uint64(len(leaves)) {
		return fmt.Errorf("tree head size mismatch: stored %d, log has %d", head.Size, len(leaves))
	}

	storedMAC, err := hex.DecodeString(head.MAC)
	if err != nil || len(storedMAC) != 32 {
		return errors.New("tree head: malformed MAC")
	}
	expected := computeMAC(key, uint64(len(leaves)), root)
	if !macEqual(expected[:], storedMAC) {
		return errors.New("tree head MAC failed — tree head may have been tampered")
	}

	if head.Signature != "" {
		rawSig, err := hex.DecodeString(head.Signature)
		if err != nil || len(rawSig) != ed25519.SignatureSize {
			return errors.New("tree head: malformed signature")
		}
		pubBytes, err := hex.DecodeString(head.SignerKey)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return errors.New("tree head: malformed signer_key")
		}
		if s != nil && !bytes.Equal(pubBytes, s.PublicKey()) {
			return fmt.Errorf("%w (head key %s, this witness's key %s)",
				store.ErrUnexpectedSigner, head.SignerKey, hex.EncodeToString(s.PublicKey()))
		}
		if !ed25519.Verify(ed25519.PublicKey(pubBytes), sigInput(uint64(len(leaves)), root), rawSig) {
			return errors.New("tree head signature verification failed")
		}
	}
	return nil
}

// macEqual is store.macEqual.
func macEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ── Port from cmd/witness/audit.go ──────────────────────────────────────────

// AuditResult is the outcome of `witness audit`: "ok", "tamper" (exit 1) or
// "behind" (the mirror lags; exit 0 with a warning).
type AuditResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Audit compares the local log's head (as store.Head computes it from the
// leaves) with the head held by the mirror, as `witness audit` does.
func Audit(leaves [][32]byte, remote store.TreeHead) AuditResult {
	root := merkle.Root(leaves)
	localSize, localRoot := uint64(len(leaves)), hex.EncodeToString(root[:])
	switch {
	case remote.Size > localSize:
		return AuditResult{"tamper", fmt.Sprintf("mirror disagrees: mirror claims %d leaves, local has %d", remote.Size, localSize)}
	case remote.Size == localSize:
		if localRoot != remote.Root {
			return AuditResult{"tamper", fmt.Sprintf("mirror disagrees: size=%d but root mismatch", localSize)}
		}
		return AuditResult{"ok", fmt.Sprintf("local and mirror agree: leaves=%d", localSize)}
	default:
		// Since v3.3.3: the log cut to the mirror's size must still have the
		// mirror's root (store.RootAt), or history before it was rewritten.
		prefix := merkle.Root(leaves[:remote.Size])
		if hex.EncodeToString(prefix[:]) != remote.Root {
			return AuditResult{"tamper", "mirror disagrees: the local log does not extend the mirror's head"}
		}
		return AuditResult{"behind", fmt.Sprintf("mirror is %d leaf(ves) behind local", localSize-remote.Size)}
	}
}
