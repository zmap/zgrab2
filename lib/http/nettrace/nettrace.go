package nettrace

// TraceKey is a context.Context Value key. Its associated value should
// be a *Trace struct.
type TraceKey struct{}

// LookupIPAltResolverKey is a context.Context Value key used by tests to
// specify an alternate resolver func.
// It is not exposed to outsider users. (But see issue 12503)
// The value should be the same type as lookupIP:
//
//	func lookupIP(ctx context.Context, host string) ([]IPAddr, error)
type LookupIPAltResolverKey struct{}

// Trace contains a set of hooks for tracing events within
// the net package. Any specific hook may be nil.
type Trace struct {
	// DNSStart is called with the hostname of a DNS lookup
	// before it begins.
	DNSStart func(name string)

	// DNSDone is called after a DNS lookup completes (or fails).
	// The coalesced parameter is whether singleflight de-dupped
	// the call. The addrs are of type net.IPAddr but can't
	// actually be for circular dependency reasons.
	DNSDone func(netIPs []interface{}, coalesced bool, err error)

	// ConnectStart is called before a Dial, excluding Dials made
	// during DNS lookups. In the case of DualStack (Happy Eyeballs)
	// dialing, this may be called multiple times, from multiple
	// goroutines.
	ConnectStart func(network, addr string)

	// ConnectStart is called after a Dial with the results, excluding
	// Dials made during DNS lookups. It may also be called multiple
	// times, like ConnectStart.
	ConnectDone func(network, addr string, err error)
}
