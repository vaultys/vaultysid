package serviceid

import "unicode/utf8"

// decodePunycode decodes a Punycode label body (RFC 3492 §6.2), without the
// "xn--" prefix. It is used ONLY to refuse labels that cannot be decoded, as the
// WHATWG URL parser does in the TypeScript reference; the decoded form is never
// output. A label that decodes to pure ASCII is refused too: such a label is not a
// valid A-label (RFC 5891 §5.3).
func decodePunycode(input string) ([]rune, bool) {
	const (
		base        = 36
		tMin        = 1
		tMax        = 26
		skew        = 38
		damp        = 700
		initialBias = 72
		initialN    = 128
		maxInt      = 1<<31 - 1
	)
	adapt := func(delta, numPoints int, first bool) int {
		if first {
			delta /= damp
		} else {
			delta /= 2
		}
		delta += delta / numPoints
		k := 0
		for delta > ((base-tMin)*tMax)/2 {
			delta /= base - tMin
			k += base
		}
		return k + (base-tMin+1)*delta/(delta+skew)
	}
	digit := func(c byte) (int, bool) {
		switch {
		case c >= '0' && c <= '9':
			return int(c-'0') + 26, true
		case c >= 'a' && c <= 'z':
			return int(c - 'a'), true
		case c >= 'A' && c <= 'Z':
			return int(c - 'A'), true
		}
		return 0, false
	}

	n, i, bias := initialN, 0, initialBias
	var output []rune
	b := -1
	for j := len(input) - 1; j >= 0; j-- {
		if input[j] == '-' {
			b = j
			break
		}
	}
	rest := input
	if b > 0 {
		for _, c := range []byte(input[:b]) {
			if c >= 0x80 {
				return nil, false
			}
			output = append(output, rune(c))
		}
		rest = input[b+1:]
	} else if b == 0 {
		rest = input[1:]
	}
	if len(rest) == 0 {
		return nil, false
	}
	for pos := 0; pos < len(rest); {
		oldi, w := i, 1
		for k := base; ; k += base {
			if pos >= len(rest) {
				return nil, false
			}
			d, ok := digit(rest[pos])
			pos++
			if !ok || d > (maxInt-i)/w {
				return nil, false
			}
			i += d * w
			t := k - bias
			if t < tMin {
				t = tMin
			} else if t > tMax {
				t = tMax
			}
			if d < t {
				break
			}
			if w > maxInt/(base-t) {
				return nil, false
			}
			w *= base - t
		}
		bias = adapt(i-oldi, len(output)+1, oldi == 0)
		if i/(len(output)+1) > maxInt-n {
			return nil, false
		}
		n += i / (len(output) + 1)
		i %= len(output) + 1
		if n < 0x80 || n > utf8.MaxRune || (n >= 0xD800 && n <= 0xDFFF) {
			return nil, false
		}
		output = append(output[:i], append([]rune{rune(n)}, output[i:]...)...)
		i++
	}
	return output, true
}
