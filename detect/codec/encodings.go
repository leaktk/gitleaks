package codec

import (
	"math"
	"strconv"
)

// encodingNames is used to map the encodingKinds to their name
var encodingNames = []string{
	"percent",
	"unicode",
	"hex",
	"base64",
}

// encodingKind can be or'd together to capture all of the unique encodings
// that were present in a segment
type encodingKind int

var (
	// make sure these go up by powers of 2 and are in order of precedence
	// when two encodings "touch" each other. If two encodings touch or overlap,
	// the lower number here wins out as a way to handle things like percent encodings
	// in base64 etc (e.g. aGVsbG8%3D).
	noKind      = encodingKind(0)
	percentKind = encodingKind(1)
	unicodeKind = encodingKind(2)
	hexKind     = encodingKind(4)
	base64Kind  = encodingKind(8)
)

// Anchors is a lookup table for anchors for the encodings. Any character
// that is a valid first character for a supported encoding should be included
// here with the kinds it is an anchor for for its values.
var anchors = [256]encodingKind{
	'%':  percentKind,
	'+':  base64Kind,
	'-':  base64Kind,
	'/':  base64Kind,
	'0':  base64Kind | hexKind,
	'1':  base64Kind | hexKind,
	'2':  base64Kind | hexKind,
	'3':  base64Kind | hexKind,
	'4':  base64Kind | hexKind,
	'5':  base64Kind | hexKind,
	'6':  base64Kind | hexKind,
	'7':  base64Kind | hexKind,
	'8':  base64Kind | hexKind,
	'9':  base64Kind | hexKind,
	'A':  base64Kind | hexKind,
	'B':  base64Kind | hexKind,
	'C':  base64Kind | hexKind,
	'D':  base64Kind | hexKind,
	'E':  base64Kind | hexKind,
	'F':  base64Kind | hexKind,
	'G':  base64Kind,
	'H':  base64Kind,
	'I':  base64Kind,
	'J':  base64Kind,
	'K':  base64Kind,
	'L':  base64Kind,
	'M':  base64Kind,
	'N':  base64Kind,
	'O':  base64Kind,
	'P':  base64Kind,
	'Q':  base64Kind,
	'R':  base64Kind,
	'S':  base64Kind,
	'T':  base64Kind,
	'U':  base64Kind | unicodeKind,
	'V':  base64Kind,
	'W':  base64Kind,
	'X':  base64Kind,
	'Y':  base64Kind,
	'Z':  base64Kind,
	'\\': unicodeKind,
	'_':  base64Kind,
	'a':  base64Kind | hexKind,
	'b':  base64Kind | hexKind,
	'c':  base64Kind | hexKind,
	'd':  base64Kind | hexKind,
	'e':  base64Kind | hexKind,
	'f':  base64Kind | hexKind,
	'g':  base64Kind,
	'h':  base64Kind,
	'i':  base64Kind,
	'j':  base64Kind,
	'k':  base64Kind,
	'l':  base64Kind,
	'm':  base64Kind,
	'n':  base64Kind,
	'o':  base64Kind,
	'p':  base64Kind,
	'q':  base64Kind,
	'r':  base64Kind,
	's':  base64Kind,
	't':  base64Kind,
	'u':  base64Kind,
	'v':  base64Kind,
	'w':  base64Kind,
	'x':  base64Kind,
	'y':  base64Kind,
	'z':  base64Kind,
}

func (e encodingKind) String() string {
	i := int(math.Log2(float64(e)))
	if i >= len(encodingNames) {
		return ""
	}
	return encodingNames[i]
}

// kinds returns a list of encodingKinds combined in this one
func (e encodingKind) kinds() []encodingKind {
	kinds := []encodingKind{}

	for i := 0; i < len(encodingNames); i++ {
		if kind := int(e) & int(math.Pow(2, float64(i))); kind != 0 {
			kinds = append(kinds, encodingKind(kind))
		}
	}

	return kinds
}

// encodingMatch represents a match of an encoding in the text
type encodingMatch struct {
	encoding *encoding
	startEnd
}

// encoding represent a type of coding supported by the decoder.
type encoding struct {
	// the kind of decoding (e.g. base64, etc)
	kind encodingKind
	// the regex pattern that matches the encoding format
	pattern string
	// take the match and return the decoded value
	decode func(string) string
}

// findEncodingMatches finds as many encodings as it can for this pass
func findEncodingMatches(data string) []encodingMatch {
	var all []encodingMatch

	for i := 0; i < len(data); i++ {
		var se startEnd
		kind := anchors[data[i]]

		switch kind {
		case noKind:
			continue
		case percentKind:
			se = tryPercent(i, data)
		case unicodeKind:
			se = tryUnicode(i, data)
		case base64Kind:
			se = tryBase64(i, data)
		case base64Kind | unicodeKind:
			// Try unicode first since it's more specific (requires U+XXXX)
			if se = tryUnicode(i, data); se.start == i {
				kind = unicodeKind
			} else {
				se = tryBase64(i, data)
				kind = base64Kind
			}
		case base64Kind | hexKind:
			// Always try hex before base64 since base64 is a superset
			// of hex characters. The chance of the characters being all
			// valid hex characters and not base64 should be low
			if se = tryHex(i, data); se.start == i {
				kind = hexKind
			} else {
				se = tryBase64(i, data)
				kind = base64Kind
			}
		default:
			// Should not get here unless there's a bug in the code
			panic("invalid kind lookup: " + strconv.Itoa(int(kind)))
		}

		// If no match found, skip ahead to the position indicated by se.end
		if se.start == -1 {
			i = se.end - 1 // -1 because loop will increment
			continue
		}

		// Create the encoding
		var enc encoding

		switch kind {
		case percentKind:
			enc = encoding{kind: kind, decode: decodePercent}
		case unicodeKind:
			enc = encoding{kind: kind, decode: decodeUnicode}
		case hexKind:
			enc = encoding{kind: kind, decode: decodeHex}
		case base64Kind:
			enc = encoding{kind: kind, decode: decodeBase64}
		default:
			panic("could not resolve decoding; likely a missing coding wired up here")
		}

		all = append(all, encodingMatch{
			encoding: &enc,
			startEnd: se,
		})

		// Skip to end of this match
		i = se.end - 1 // -1 because loop will increment
	}

	allLen := len(all)
	filtered := make([]encodingMatch, 0, allLen)
	for i, m := range all {
		if i > 0 {
			prev := all[i-1]
			if m.overlaps(prev.startEnd) && prev.encoding.kind < m.encoding.kind {
				continue // skip this one
			}
		}

		if i+1 < allLen {
			next := all[i+1]
			if m.overlaps(next.startEnd) && next.encoding.kind < m.encoding.kind {
				continue // skip this one
			}
		}

		filtered = append(filtered, m)
	}

	return filtered
}

func tryPercent(i int, data string) startEnd {
	if i+3 > len(data) {
		return startEnd{-1, len(data)}
	}

	start := i
	for i+2 < len(data) && data[i] == '%' && hexMap[data[i+1]]|hexMap[data[i+2]] != '\xff' {
		i += 3
	}

	if start == i {
		return startEnd{-1, i + 1}
	}

	return startEnd{start, i}
}

func tryUnicode(i int, data string) startEnd {
	if i+6 > len(data) {
		// -1 to indicate no match, len(data) to indicate where it checked to for potential fast forwarding
		return startEnd{-1, len(data)}
	}

	start := i

	for i+5 < len(data) {
		switch data[i] {
		case '\\':
			// offset for skiping extra slashes
			o := i + 1
			for o+4 < len(data) && data[o] == '\\' {
				o++
			}

			// invalid hex values are set to 0xff (255); the max all valid chars could get to is 60
			if data[o]|32 == 'u' && hexMap[data[o+1]]|hexMap[data[o+1]]|hexMap[data[o+3]]|hexMap[data[o+4]] != '\xff' {
				i = o + 5
			} else {
				break
			}
		case 'U':
			// invalid values are set to 0xff (255); the max all valid chars could get to is 60
			if data[i+1] == '+' {
				if hexMap[data[i+2]]|hexMap[data[i+3]]|hexMap[data[i+4]]|hexMap[data[i+5]] != '\xff' {
					if i+6 == len(data) {
						i += 6
					} else if isWhitespace(data[i+6]) {
						i += 7
					}
				} else {
					break
				}
			}
		}
	}

	if start == i {
		return startEnd{-1, i + 1}
	}

	return startEnd{start, i}
}

func tryBase64(i int, data string) startEnd {
	// Require at least 16 base64 characters to minimize false positives
	if i+16 > len(data) {
		return startEnd{-1, len(data)}
	}

	// Find the end of the base64 run
	end := i + 1
	for end < len(data) && base64Map[data[end]] != 0xff {
		end++
	}

	// Check if we found at least 16 characters
	if end-i < 16 {
		return startEnd{-1, end}
	}

	// Check for padding characters and include them
	for end < len(data) && data[end] == '=' {
		end++
	}

	return startEnd{i, end}
}

func tryHex(i int, data string) startEnd {
	// Require at least 32 hex characters
	if i+32 > len(data) {
		return startEnd{-1, len(data)}
	}

	// Check first 32 characters - unrolled in blocks of 8 for better performance
	// Accumulate OR of all lookups - if any are invalid (0xff), the result will contain 0xff
	var acc byte

	// Block 1: chars 0-7
	acc |= hexMap[data[i+0]]
	acc |= hexMap[data[i+1]]
	acc |= hexMap[data[i+2]]
	acc |= hexMap[data[i+3]]
	acc |= hexMap[data[i+4]]
	acc |= hexMap[data[i+5]]
	acc |= hexMap[data[i+6]]
	acc |= hexMap[data[i+7]]

	// Block 2: chars 8-15
	acc |= hexMap[data[i+8]]
	acc |= hexMap[data[i+9]]
	acc |= hexMap[data[i+10]]
	acc |= hexMap[data[i+11]]
	acc |= hexMap[data[i+12]]
	acc |= hexMap[data[i+13]]
	acc |= hexMap[data[i+14]]
	acc |= hexMap[data[i+15]]

	// Block 3: chars 16-23
	acc |= hexMap[data[i+16]]
	acc |= hexMap[data[i+17]]
	acc |= hexMap[data[i+18]]
	acc |= hexMap[data[i+19]]
	acc |= hexMap[data[i+20]]
	acc |= hexMap[data[i+21]]
	acc |= hexMap[data[i+22]]
	acc |= hexMap[data[i+23]]

	// Block 4: chars 24-31
	acc |= hexMap[data[i+24]]
	acc |= hexMap[data[i+25]]
	acc |= hexMap[data[i+26]]
	acc |= hexMap[data[i+27]]
	acc |= hexMap[data[i+28]]
	acc |= hexMap[data[i+29]]
	acc |= hexMap[data[i+30]]
	acc |= hexMap[data[i+31]]

	// If any character was invalid, acc will have 0xff bits set
	if acc == 0xff {
		// don't skip ahead here because it could be base64 still
		return startEnd{-1, i}
	}

	// Found valid 32-char run, now continue until we hit a non-hex character
	end := i + 32
	for end < len(data) && hexMap[data[end]] != 0xff {
		end++
	}

	return startEnd{i, end}
}
