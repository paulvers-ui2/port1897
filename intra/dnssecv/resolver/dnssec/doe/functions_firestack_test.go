package doe

import "testing"

// Tests for FIRESTACK PATCH P6 (canonical octet decoding for NSEC ordering).
func TestCanonicalDecodeEscaped(t *testing.T) {
	cases := map[string]string{
		`a\200b`: "a\xc8b", // one octet, not UTF-8 C3 88
		`\000`:   "\x00",
		`\255`:   "\xff",
		`\065bc`: "abc", // escaped 'A' is lowercased
		`a\.b`:   "a.b",
		`a\\b`:   `a\b`,
		`x\999`:  `x\999`, // out of range: kept literally
		`Plain`:  "plain",
		`trail\`: `trail\`,
	}
	for in, want := range cases {
		if got := canonicalDecodeEscaped(in); got != want {
			t.Errorf("canonicalDecodeEscaped(%q) = %q, want %q", in, got, want)
		}
	}
}

// RFC 4034 §6.1 example ordering, plus a high-octet case that the
// upstream rune-based decoding got wrong.
func TestCanonicalCmpOrder(t *testing.T) {
	ordered := []string{
		"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.",
		"zABC.a.EXAMPLE.", "z.example.", `\001.z.example.`, "*.z.example.",
		`\200.z.example.`,
	}
	for i := 0; i+1 < len(ordered); i++ {
		if c := canonicalCmp(ordered[i], ordered[i+1]); c != -1 {
			t.Errorf("canonicalCmp(%q, %q) = %d, want -1", ordered[i], ordered[i+1], c)
		}
	}
	// \200 (0xC8) must sort after \177 (0x7F) but before \255 (0xFF).
	if canonicalCmp(`\177.z.`, `\200.z.`) != -1 || canonicalCmp(`\200.z.`, `\255.z.`) != -1 {
		t.Error("high-octet ordering wrong")
	}
}
