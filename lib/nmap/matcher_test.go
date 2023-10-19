package nmap

import (
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/stretchr/testify/require"

	"github.com/zmap/zgrab2/lib/nmap/template"
)

func TestMatcher(t *testing.T) {
	m, err := MakeMatcher(ServiceProbe{}, Match{
		MatchPattern: MatchPattern{
			Regex: `(A+(B+)?)(C+)\xFF!`,
		},
		Info: Info[Template]{
			VendorProductName: template.Parse(b(`p:$1`)),
			Version:           template.Parse(b(`v:$2`)),
			Info:              template.Parse(b(`i:$1-$2`)),
			Hostname:          template.Parse(b(`h:$3`)),
			OS:                template.Parse(b(`o:$2/$3`)),
			DeviceType:        template.Parse(b(`d:$3...$3`)),
			CPE: []Template{
				template.Parse(b(`cpe:/a:$1`)),
				template.Parse(b(`cpe:/b:$2`)),
			},
		},
	})
	require.NoError(t, err)

	r := m.MatchBytes([]byte("AAABBCCCC\xFF!"))
	require.NoError(t, r.Err())
	require.True(t, r.Found())

	v := r.Render(m.Info)
	require.Equal(t, "p:AAABB", v.VendorProductName)
	require.Equal(t, "v:BB", v.Version)
	require.Equal(t, "i:AAABB-BB", v.Info)
	require.Equal(t, "h:CCCC", v.Hostname)
	require.Equal(t, "o:BB/CCCC", v.OS)
	require.Equal(t, "d:CCCC...CCCC", v.DeviceType)
	require.Equal(t, []string{"cpe:/a:AAABB", "cpe:/b:BB"}, v.CPE)
}

func TestIntoRunes(t *testing.T) {
	bin := []byte("A\x80\xFF\x00Я")
	require.Equal(t, []rune{'A', 0x80, 0xFF, 0, 'Я'}, intoRunes(bin))
}

func TestMatchBinaryInput(t *testing.T) {
	// Binary input (invalid utf-8 string)
	bin := []byte("A\x80\xFF\x00Я")
	re := regexp2.MustCompile(`^A\x80\xFF\0Я$`, regexp2.None)

	// Wrong conversion
	m, err := re.FindStringMatch(string(bin))
	require.NoError(t, err)
	require.False(t, m != nil)

	// Wrong conversion
	m, err = re.FindRunesMatch([]rune(string(bin)))
	require.NoError(t, err)
	require.False(t, m != nil)

	// Right conversion
	m, err = re.FindRunesMatch(intoRunes(bin))
	require.NoError(t, err)
	require.True(t, m != nil)
}

func TestMatcherRegexpSingleLine(t *testing.T) {
	m, err := MakeMatcher(ServiceProbe{}, Match{
		MatchPattern: MatchPattern{
			Regex: `abc.+def`,
		},
	})

	require.NoError(t, err)

	r := m.MatchBytes([]byte("abc\r\ndef"))
	require.NoError(t, r.Err())
	require.True(t, r.Found())
}
