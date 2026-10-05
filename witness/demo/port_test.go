package demo

// The ports in demo.go must agree with the real store. Each case writes a log
// to disk with store.Append, tampers with the files as an attacker would, and
// requires store.Open and VerifyHead to reach the same verdict and error.

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bigblue-r4/sgail-playground/witness/internal/encrypt"
	"github.com/bigblue-r4/sgail-playground/witness/internal/signer"
	"github.com/bigblue-r4/sgail-playground/witness/internal/store"
)

type realLog struct {
	dir string
	key []byte
	s   signer.Signer
}

// writeReal records FarmNight with the real store and returns what it wrote.
func writeReal(t *testing.T) (realLog, []store.Entry, store.TreeHead) {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	s, err := signer.NewDev(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, key, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range FarmNight {
		if err := st.Append(f.Level, f.Event, "farm", json.RawMessage(f.Data)); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.Close()
	entries, err := store.ReadAll(dir, key)
	if err != nil || len(entries) != len(FarmNight) {
		t.Fatalf("read back: %v (%d entries)", err, len(entries))
	}
	return realLog{dir, key, s}, entries, readHead(t, dir)
}

func readHead(t *testing.T, dir string) store.TreeHead {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "tree-head.json"))
	if err != nil {
		t.Fatal(err)
	}
	var h store.TreeHead
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// rewriteLog replaces witness.log with these entries, encrypted and framed
// exactly as store.Append writes them: what someone holding the key can do.
func (r realLog) rewriteLog(t *testing.T, entries []store.Entry) {
	t.Helper()
	var out []byte
	for _, e := range entries {
		plain, _ := json.Marshal(e)
		sealed, err := encrypt.Seal(plain, r.key)
		if err != nil {
			t.Fatal(err)
		}
		out = binary.BigEndian.AppendUint32(out, uint32(len(sealed)))
		out = append(out, sealed...)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "witness.log"), out, 0600); err != nil {
		t.Fatal(err)
	}
}

func (r realLog) writeHead(t *testing.T, h store.TreeHead) {
	t.Helper()
	b, _ := json.MarshalIndent(h, "", "  ")
	if err := os.WriteFile(filepath.Join(r.dir, "tree-head.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}

// sameVerdict opens the tampered store for real and compares with the port.
func sameVerdict(t *testing.T, r realLog, entries []store.Entry, head *store.TreeHead) error {
	t.Helper()
	st, realErr := store.Open(r.dir, r.key, r.s)
	if st != nil {
		_ = st.Close()
	}
	portErr := VerifyHead(r.key, head, Leaves(entries))
	if (realErr == nil) != (portErr == nil) {
		t.Fatalf("verdicts differ: store.Open=%v port=%v", realErr, portErr)
	}
	if realErr != nil && !strings.Contains(realErr.Error(), portErr.Error()) {
		t.Fatalf("errors differ:\n store.Open: %v\n port:       %v", realErr, portErr)
	}
	return portErr
}

func TestMakeHeadWritesTheSameHeadAsTheStore(t *testing.T) {
	r, entries, head := writeReal(t)
	got, err := MakeHead(r.key, r.s, Leaves(entries), head.PrevRoot, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != head.Size || got.Root != head.Root || got.MAC != head.MAC ||
		got.Signature != head.Signature || got.SignerKey != head.SignerKey {
		t.Fatalf("port head differs from store head:\n port  %+v\n store %+v", got, head)
	}
}

func TestPortAgreesWithTheStoreOnEveryTamper(t *testing.T) {
	cases := []struct {
		name    string
		tamper  func([]store.Entry) []store.Entry
		wantErr string
	}{
		{"untouched", func(e []store.Entry) []store.Entry { return e }, ""},
		{"edit an entry", func(e []store.Entry) []store.Entry {
			e[2].Data = json.RawMessage(`{"by":"crew:ana"}`)
			return e
		}, "root mismatch"},
		{"delete an entry", func(e []store.Entry) []store.Entry {
			return append(e[:2:2], e[3:]...)
		}, "root mismatch"},
		{"cut off the end", func(e []store.Entry) []store.Entry { return e[:5] }, "root mismatch"},
		{"swap two entries", func(e []store.Entry) []store.Entry {
			e[3], e[4] = e[4], e[3]
			return e
		}, "root mismatch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, entries, head := writeReal(t)
			tampered := c.tamper(entries)
			r.rewriteLog(t, tampered)
			err := sameVerdict(t, r, tampered, &head)
			if c.wantErr == "" && err != nil || c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("got %v, want %q", err, c.wantErr)
			}
		})
	}
}

func TestPortAgreesWhenTheHeadFileIsDeleted(t *testing.T) {
	r, entries, _ := writeReal(t)
	if err := os.Remove(filepath.Join(r.dir, "tree-head.json")); err != nil {
		t.Fatal(err)
	}
	if err := sameVerdict(t, r, entries, nil); err != store.ErrMissingTreeHead {
		t.Fatalf("got %v, want ErrMissingTreeHead", err)
	}
}

func TestPortAgreesOnAForgedHead(t *testing.T) {
	r, entries, head := writeReal(t)
	tampered := append(entries[:2:2], entries[3:]...)
	r.rewriteLog(t, tampered)
	forged, _ := MakeHead(r.key, r.s, Leaves(tampered), head.PrevRoot, time.Now())

	// Without the machine key the MAC can't be made.
	bad := forged
	bad.MAC = strings.Repeat("00", 32)
	r.writeHead(t, bad)
	if err := sameVerdict(t, r, tampered, &bad); err == nil || !strings.Contains(err.Error(), "MAC failed") {
		t.Fatalf("got %v, want MAC failure", err)
	}

	// With full control of the machine, the cover-up passes the local check.
	// This is the limit the page shows; the mirror is what catches it.
	r.writeHead(t, forged)
	if err := sameVerdict(t, r, tampered, &forged); err != nil {
		t.Fatalf("a re-signed head should pass the local check, got %v", err)
	}
}

func TestAuditMatchesWitnessAudit(t *testing.T) {
	_, entries, head := writeReal(t)
	leaves := Leaves(entries)
	if a := Audit(leaves, head); a.Status != "ok" {
		t.Fatalf("same log: %+v", a)
	}
	if a := Audit(leaves[:5], head); a.Status != "tamper" || !strings.Contains(a.Message, "mirror claims 8 leaves, local has 5") {
		t.Fatalf("truncated: %+v", a)
	}
	other := append([][32]byte{}, leaves...)
	other[0][0] ^= 1
	if a := Audit(other, head); a.Status != "tamper" || !strings.Contains(a.Message, "root mismatch") {
		t.Fatalf("rewritten: %+v", a)
	}
	behind := head
	behind.Size = 6
	if a := Audit(leaves, behind); a.Status != "behind" {
		t.Fatalf("mirror behind: %+v", a)
	}
}
