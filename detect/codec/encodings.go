package codec

import (
	"fmt"
	"math"
	"strings"

	"github.com/zricethezav/gitleaks/v8/regexp"
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
	// make sure these go up by powers of 2
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
	// determine which encoding should win out when two overlap
	precedence int
}

func init() {
	count := len(encodings)
	namedPatterns := make([]string, count)
	for i, encoding := range encodings {
		encoding.precedence = count - i
		namedPatterns[i] = fmt.Sprintf(
			"(?P<%s>%s)",
			encoding.kind,
			encoding.pattern,
		)
	}
	encodingsRe = regexp.MustCompile(strings.Join(namedPatterns, "|"))
}

// findEncodingMatches finds as many encodings as it can for this pass
func findEncodingMatches(data string) []encodingMatch {
	var all []encodingMatch
	for _, matchIndex := range encodingsRe.FindAllStringSubmatchIndex(data, -1) {
		// Add the encodingMatch with its proper encoding
		for i, j := 2, 0; i < len(matchIndex); i, j = i+2, j+1 {
			if matchIndex[i] > -1 {
				all = append(all, encodingMatch{
					encoding: encodings[j],
					startEnd: startEnd{
						start: matchIndex[i],
						end:   matchIndex[i+1],
					},
				})
			}
		}
	}

	totalMatches := len(all)
	if totalMatches == 1 {
		return all
	}

	// filter out lower precedence ones that overlap their neigbors
	filtered := make([]encodingMatch, 0, len(all))
	for i, m := range all {
		if i > 0 {
			prev := all[i-1]
			if m.overlaps(prev.startEnd) && prev.encoding.precedence > m.encoding.precedence {
				continue // skip this one
			}
		}
		if i+1 < totalMatches {
			next := all[i+1]
			if m.overlaps(next.startEnd) && next.encoding.precedence > m.encoding.precedence {
				continue // skip this one
			}
		}
		filtered = append(filtered, m)
	}

	return filtered
}

func findEncodingIndices(data string) {
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
	}
}
