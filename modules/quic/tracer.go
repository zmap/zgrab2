package quic

import (
	"sync"

	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// handshakeTracer collects the details of a handshake that quic-go does not
// expose through its connection state (the server's transport parameters and
// whether a Retry was received) from quic-go's qlog events. It implements both
// qlogwriter.Trace and qlogwriter.Recorder, and is safe for concurrent use.
type handshakeTracer struct {
	mu              sync.Mutex
	serverParams    *qlog.ParametersSet
	retryReceived   bool
	packetsReceived int
}

var (
	_ qlogwriter.Trace    = (*handshakeTracer)(nil)
	_ qlogwriter.Recorder = (*handshakeTracer)(nil)
)

// AddProducer implements qlogwriter.Trace.
func (t *handshakeTracer) AddProducer() qlogwriter.Recorder {
	return t
}

// RecordEvent implements qlogwriter.Recorder.
func (t *handshakeTracer) RecordEvent(ev qlogwriter.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch e := ev.(type) {
	case qlog.ParametersSet:
		if e.SentBy.String() == "server" {
			params := e
			t.serverParams = &params
		}
	case qlog.PacketReceived:
		t.packetsReceived++
		if e.Header.PacketType == qlog.PacketTypeRetry {
			t.retryReceived = true
		}
	case qlog.VersionNegotiationReceived:
		t.packetsReceived++
	}
}

// Close implements qlogwriter.Recorder.
func (t *handshakeTracer) Close() error {
	return nil
}

// fill copies what the tracer has seen so far into log.
func (t *handshakeTracer) fill(log *HandshakeLog) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log.RetryReceived = log.RetryReceived || t.retryReceived
	log.serverResponded = log.serverResponded || t.packetsReceived > 0
	if p := t.serverParams; p != nil {
		log.TransportParameters = &TransportParameters{
			MaxIdleTimeoutMS:               p.MaxIdleTimeout.Milliseconds(),
			MaxUDPPayloadSize:              int64(p.MaxUDPPayloadSize),
			InitialMaxData:                 int64(p.InitialMaxData),
			InitialMaxStreamDataBidiLocal:  int64(p.InitialMaxStreamDataBidiLocal),
			InitialMaxStreamDataBidiRemote: int64(p.InitialMaxStreamDataBidiRemote),
			InitialMaxStreamDataUni:        int64(p.InitialMaxStreamDataUni),
			InitialMaxStreamsBidi:          p.InitialMaxStreamsBidi,
			InitialMaxStreamsUni:           p.InitialMaxStreamsUni,
			AckDelayExponent:               p.AckDelayExponent,
			MaxAckDelayMS:                  p.MaxAckDelay.Milliseconds(),
			ActiveConnectionIDLimit:        p.ActiveConnectionIDLimit,
			DisableActiveMigration:         p.DisableActiveMigration,
			StatelessResetToken:            p.StatelessResetToken != nil,
			PreferredAddress:               p.PreferredAddress != nil,
			ResetStreamAt:                  p.EnableResetStreamAt,
		}
		// A negative value means the parameter was absent (no datagram support).
		if p.MaxDatagramFrameSize >= 0 {
			size := int64(p.MaxDatagramFrameSize)
			log.TransportParameters.MaxDatagramFrameSize = &size
		}
	}
}
