package znet

import (
	"math/rand"
	"net"
)

// AddressSelector abstracts the selection of a network address from the code
// that needs to specify it.
type AddressSelector interface {
	Address() net.Addr
}

// DefaultAddressSelector is an AddressSelector that always returns nil, which
// will cause most net API calls to let the operating system choose the address.
type DefaultAddressSelector struct{}

// Address returns nil
func (das DefaultAddressSelector) Address() net.Addr {
	return nil
}

// FixedAddressSelector is an AddressSelector that always returns the same
// address. It is implemented as an alias for net.Addr. To create one, simply
// assign a net.Addr.
type FixedAddressSelector net.Addr

// Address is the identity function.
func (fas FixedAddressSelector) Address() {
	return fas
}

// AddressSliceSelector selects a random address from the provided slice. For
// empty slices, it behaves the same as the DefaultAddressSelector.
type AddressSliceSelector struct {
	Addresses []net.Addr
}

// Address uses math.rand to select a net.Addr from Addresses.
func (ss *AddressSliceSelector) Address() net.Addr {
	n := len(ss.Addresses)
	if n == 0 {
		return nil
	}
	idx := rand.Intn(n)
	return ss.Addresses[idx]
}
