package nmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatcher(t *testing.T) {
	m, err := MakeMatcher(ServiceProbe{}, Match{
		MatchPattern: MatchPattern{
			Regex: `(A+(B+)?)(C+)\0!`,
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

	r := m.MatchRunes([]rune("AAABBCCCC\x00!"))
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

func TestMatchInvalidRunes(t *testing.T) {
	m, err := MakeMatcher(ServiceProbe{},
		Match{
			MatchPattern: MatchPattern{Regex: "^A\x80Я$"}})
	require.NoError(t, err)

	// Unfortunatelly, regexp2 does not support matching binary data.
	r := m.MatchRunes([]rune{'A', 0x80, 'Я'})
	require.False(t, r.Found())
}
