package znet

import (
	"net"
	"time"
)

type DialerConstructor interface {
	Dialer() *net.Dialer
}

type PreConfiguredDialer struct {
	AddressSelector AddressSelector
	Timeout         time.Duration
}

func (pcd *PreConfiguredDialer) Dialer() *net.Dialer {
	return &net.Dialer{
		LocalAddr: pcd.AddressSelector.Address(),
		Timeout:   pcd.Timeout,
	}
}
