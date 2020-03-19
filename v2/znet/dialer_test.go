package znet

import (
	"testing"

	"gotest.tools/assert"
)

type pcdTest struct {
	pcd PreConfiguredDialer
}

func TestPreConfiguredDialer(t *testing.T) {
	pcdTests := []pcdTest{
		pcdTest{
			pcd: PreConfiguredDialer{
				AddressSelector: DefaultAddressSelector{},
			},
		},
	}
	for _, test := range pcdTests {
		dialer := test.pcd.Dialer()
		assert.Check(t, dialer.Deadline.IsZero())
	}
}
