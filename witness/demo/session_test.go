package demo

import (
	"strings"
	"testing"

	"github.com/bigblue-r4/sgail-playground/witness/internal/merkle"
)

func fresh(t *testing.T) *Session {
	t.Helper()
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHonestLogPassesBothChecks(t *testing.T) {
	st := fresh(t).State()
	if !st.Verify.OK || !st.Audit.OK || st.Audit.Status != "ok" {
		t.Fatalf("verify=%+v audit=%+v", st.Verify, st.Audit)
	}
	if len(st.Entries) != len(FarmNight) || st.Head.Signature == "" {
		t.Fatalf("entries=%d head=%+v", len(st.Entries), st.Head)
	}
}

func TestEveryAttackOnTheLogIsCaught(t *testing.T) {
	cases := []struct {
		name   string
		attack func(*Session) error
		verify string // "" = local check passes
		audit  string
	}{
		{"edit", func(s *Session) error { return s.Edit(2, `{"by":"crew:ana"}`) }, "root mismatch", "fail"},
		{"delete", func(s *Session) error { return s.Delete(2) }, "root mismatch", "fail"},
		{"truncate", func(s *Session) error { s.Truncate(4); return nil }, "root mismatch", "fail"},
		{"delete head", func(s *Session) error { s.DeleteHead(); return nil }, "tree head missing", "fail"},
		{"delete + re-sign", func(s *Session) error {
			if err := s.Delete(2); err != nil {
				return err
			}
			return s.Resign()
		}, "", "tamper"},
		{"edit + re-sign", func(s *Session) error {
			if err := s.Edit(2, `{"by":"crew:ana"}`); err != nil {
				return err
			}
			return s.Resign()
		}, "", "tamper"},
		{"delete head + re-sign", func(s *Session) error {
			s.Truncate(3)
			s.DeleteHead()
			return s.Resign()
		}, "", "tamper"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := fresh(t)
			if err := c.attack(s); err != nil {
				t.Fatal(err)
			}
			st := s.State()
			if c.verify == "" {
				if !st.Verify.OK {
					t.Fatalf("local check should pass after a re-sign: %+v", st.Verify)
				}
			} else if st.Verify.OK || !strings.Contains(st.Verify.Message, c.verify) {
				t.Fatalf("verify = %+v, want failure containing %q", st.Verify, c.verify)
			}
			if st.Audit.OK || st.Audit.Status != c.audit {
				t.Fatalf("audit = %+v, want %s", st.Audit, c.audit)
			}
		})
	}
}

func TestEditTurnsExactlyTheLeafToRootPathRed(t *testing.T) {
	s := fresh(t)
	if err := s.Edit(2, `{"by":"crew:ana"}`); err != nil {
		t.Fatal(err)
	}
	var changed []string
	var walk func(n *Node, path string)
	walk = func(n *Node, path string) {
		if n.Changed {
			changed = append(changed, path)
		}
		for i, c := range n.Children {
			walk(c, path+string(rune('0'+i)))
		}
	}
	tree := s.State().Tree
	walk(tree, "r")
	// leaf 2 of 8 = left, right, left
	if strings.Join(changed, " ") != "r r0 r01 r010" {
		t.Fatalf("changed nodes = %v", changed)
	}
}

func TestDiagramTreeHasTheWitnessRoot(t *testing.T) {
	for n := 1; n <= 9; n++ {
		s := fresh(t)
		s.Truncate(len(FarmNight) - min(n, len(FarmNight)))
		leaves := Leaves(s.Entries)
		root := merkle.Root(leaves)
		if got := Tree(leaves).raw; got != root {
			t.Fatalf("n=%d: diagram root differs from merkle.Root", n)
		}
	}
}

func TestBadEditsAreRefused(t *testing.T) {
	s := fresh(t)
	if err := s.Edit(2, `{not json`); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if err := s.Edit(99, `{}`); err == nil {
		t.Fatal("out-of-range edit accepted")
	}
	if err := s.Delete(-1); err == nil {
		t.Fatal("out-of-range delete accepted")
	}
}

func TestSavingAnEntryUnchangedIsNotTampering(t *testing.T) {
	s := fresh(t)
	pretty := "{\n \"source\": \"house-3/controller\",\n \"kind\": \"setting_change\",\n \"setting\": \"min_ventilation_pct\",\n \"from\": 30,\n \"to\": 10,\n \"by\": \"remote:jdoe\"\n}"
	if err := s.Edit(2, pretty); err != nil {
		t.Fatal(err)
	}
	if st := s.State(); !st.Verify.OK || !st.Audit.OK {
		t.Fatalf("an unchanged save was flagged: %+v %+v", st.Verify, st.Audit)
	}
}
