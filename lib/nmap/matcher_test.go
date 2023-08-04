package nmap

import (
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/stretchr/testify/require"
)

func TestMatcher(t *testing.T) {
	m, err := MakeMatcher(ServiceProbe{}, Match{
		MatchPattern: MatchPattern{
			Regex: `(A+(B+)?)(C+)\xFF!`,
			Flags: `s`,
		},
		VersionInfo: VersionInfo{
			VendorProductName: `p:$1`,
			Version:           `v:$2`,
			Info:              `i:$1-$2`,
			Hostname:          `h:$3`,
			OS:                `o:$2/$3`,
			DeviceType:        `d:$3...$3`,
			CPE:               []string{"cpe:/a:$1", "cpe:/b:$2"},
		},
	})
	require.NoError(t, err)

	r := m.MatchBytes([]byte("AAABBCCCC\xFF!"))
	require.NoError(t, r.Err())
	require.True(t, r.Found())

	v := r.Render(m.VersionInfo)
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
