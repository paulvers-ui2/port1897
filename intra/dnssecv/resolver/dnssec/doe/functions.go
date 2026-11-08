package doe

import (
	"github.com/miekg/dns"
	"strings"
)

// wildcardName replaces the first label with `*`
func wildcardName(name string) string {
	labelIndexes := dns.Split(name)
	if len(labelIndexes) < 2 {
		return "*."
	}
	return "*." + name[labelIndexes[1]:]
}

func canonicalCmp(a, b string) int {
	labelsA := dns.SplitDomainName(dns.CanonicalName(a))
	labelsB := dns.SplitDomainName(dns.CanonicalName(b))
	// FIRESTACK PATCH (P9): SplitDomainName returns nil for the root; the
	// root sorts before every other name.
	if len(labelsA) == 0 || len(labelsB) == 0 {
		switch {
		case len(labelsA) == len(labelsB):
			return 0
		case len(labelsA) == 0:
			return -1
		default:
			return 1
		}
	}

	minLength := min(len(labelsA), len(labelsB))

	for i := 1; i <= minLength; i++ {
		labelA := labelsA[len(labelsA)-i]
		labelB := labelsB[len(labelsB)-i]

		// Convert labels to lowercase and decode escaped characters
		if strings.Contains(labelA, `\`) {
			labelA = canonicalDecodeEscaped(labelA)
		}
		if strings.Contains(labelB, `\`) {
			labelB = canonicalDecodeEscaped(labelB)
		}

		// Compare lexicographically
		if labelA != labelB {
			if labelA < labelB {
				return -1
			}
			return 1
		}
	}

	// If labels are identical so far, the shorter one sorts first
	if len(labelsA) < len(labelsB) {
		return -1
	} else if len(labelsA) > len(labelsB) {
		return 1
	}
	return 0
}

// canonicalDecodeEscaped turns a presentation-format label into its wire
// octets for RFC 4034 §6.1 canonical ordering.
//
// FIRESTACK PATCH (P6): upstream decoded `\DDD` with string(rune(n)), which
// emits UTF-8, so `\200` became the two bytes C3 88 instead of the single
// octet 0xC8, and values above 255 were accepted. It also left `\X` escapes
// (e.g. `\.`) undecoded and did not lowercase escaped ASCII letters. Each of
// these can mis-order NSEC owner names and so break denial-of-existence
// proofs. Now: `\DDD` (0-255 only) -> one octet; `\X` -> X; A-Z -> a-z.
// An out-of-range `\DDD` is kept verbatim (miekg/dns rejects such names).
func canonicalDecodeEscaped(label string) string {
	out := make([]byte, 0, len(label))
	for i := 0; i < len(label); i++ {
		c := label[i]
		if c == '\\' && i+1 < len(label) {
			if i+3 < len(label) && canonicalIsDigit(label[i+1]) && canonicalIsDigit(label[i+2]) && canonicalIsDigit(label[i+3]) {
				n := int(label[i+1]-'0')*100 + int(label[i+2]-'0')*10 + int(label[i+3]-'0')
				if n <= 255 {
					out = append(out, lowerASCII(byte(n))) // #nosec G115 -- n <= 255 checked above
					i += 3
					continue
				}
				out = append(out, c) // invalid escape: keep literally
				continue
			}
			out = append(out, lowerASCII(label[i+1]))
			i++
			continue
		}
		out = append(out, lowerASCII(c))
	}
	return string(out)
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// Check if a character is a digit
func canonicalIsDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
