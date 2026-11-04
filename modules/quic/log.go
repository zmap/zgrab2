package quic

import (
	"fmt"

	ztls "github.com/zmap/zcrypto/tls"
)

// Log is the output of a QUIC scan.
type Log struct {
	// VersionNegotiation holds the server's answer to a packet carrying a
	// reserved QUIC version, if it sent one.
	VersionNegotiation *VersionNegotiationLog `json:"version_negotiation,omitempty"`

	// Handshake holds the result of the QUIC (TLS 1.3) handshake, if it was
	// attempted.
	Handshake *HandshakeLog `json:"handshake,omitempty"`
}

// Version is a QUIC version number along with its name, when known.
type Version struct {
	// Value is the version number as an 8-digit hex string, e.g. "0x00000001".
	Value string `json:"value"`

	// Name is a human-readable name for the version, such as "QUICv1",
	// "draft-29" or "gQUIC-Q050", if the version is recognized.
	Name string `json:"name,omitempty"`
}

func newVersion(v uint32) Version {
	return Version{Value: fmt.Sprintf("0x%08x", v), Name: versionName(v)}
}

// VersionNegotiationLog describes a Version Negotiation packet sent by the
// server (RFC 9000, Section 6).
type VersionNegotiationLog struct {
	// SupportedVersions lists the versions the server advertised, in the order
	// it sent them. Servers may include reserved versions to exercise version
	// negotiation; those have the name "reserved".
	SupportedVersions []Version `json:"supported_versions"`

	// ConnectionIDsEchoed is true if the packet's connection IDs mirror the
	// ones in the probe, as RFC 9000 requires. A mismatch can indicate a
	// middlebox or a non-conforming implementation.
	ConnectionIDsEchoed bool `json:"connection_ids_echoed"`
}

// HandshakeLog describes a QUIC handshake attempt.
type HandshakeLog struct {
	// Complete is true if the handshake completed.
	Complete bool `json:"complete"`

	// Version is the negotiated QUIC version.
	Version *Version `json:"version,omitempty"`

	// OfferedALPN lists the application protocols offered by the scanner.
	OfferedALPN []string `json:"offered_alpn,omitempty"`

	// ALPN is the application protocol selected by the server.
	ALPN string `json:"alpn,omitempty"`

	// ServerName is the SNI value sent, if any.
	ServerName string `json:"server_name,omitempty"`

	// TLSVersion is the negotiated TLS version (always TLS 1.3 for QUIC).
	TLSVersion string `json:"tls_version,omitempty"`

	// CipherSuite is the negotiated TLS 1.3 cipher suite.
	CipherSuite string `json:"cipher_suite,omitempty"`

	// Certificates is the certificate chain presented by the server, leaf
	// first, in the same raw/parsed form as the tls module. Certificates are
	// not validated.
	Certificates []ztls.SimpleCertificate `json:"certificates,omitempty"`

	// RetryReceived is true if the server answered the first Initial with a
	// Retry packet (address validation, RFC 9000 Section 8.1.2).
	RetryReceived bool `json:"retry_received"`

	// TransportParameters are the QUIC transport parameters sent by the
	// server.
	TransportParameters *TransportParameters `json:"transport_parameters,omitempty"`

	// VersionNegotiationFailed is set when none of the versions the server
	// offered during the handshake are supported by the scanner.
	VersionNegotiationFailed bool `json:"version_negotiation_failed,omitempty"`

	// CloseError describes how the connection was closed if the handshake
	// failed.
	CloseError *CloseError `json:"close_error,omitempty"`

	// serverResponded is set if any packet was received from the server.
	serverResponded bool
}

// TransportParameters are the server's QUIC transport parameters (RFC 9000,
// Section 18.2). Values that the server did not send are reported with their
// protocol defaults.
type TransportParameters struct {
	MaxIdleTimeoutMS               int64  `json:"max_idle_timeout_ms"`
	MaxUDPPayloadSize              int64  `json:"max_udp_payload_size"`
	InitialMaxData                 int64  `json:"initial_max_data"`
	InitialMaxStreamDataBidiLocal  int64  `json:"initial_max_stream_data_bidi_local"`
	InitialMaxStreamDataBidiRemote int64  `json:"initial_max_stream_data_bidi_remote"`
	InitialMaxStreamDataUni        int64  `json:"initial_max_stream_data_uni"`
	InitialMaxStreamsBidi          int64  `json:"initial_max_streams_bidi"`
	InitialMaxStreamsUni           int64  `json:"initial_max_streams_uni"`
	AckDelayExponent               uint8  `json:"ack_delay_exponent"`
	MaxAckDelayMS                  int64  `json:"max_ack_delay_ms"`
	ActiveConnectionIDLimit        uint64 `json:"active_connection_id_limit"`
	MaxDatagramFrameSize           *int64 `json:"max_datagram_frame_size,omitempty"`
	DisableActiveMigration         bool   `json:"disable_active_migration"`
	StatelessResetToken            bool   `json:"stateless_reset_token"`
	PreferredAddress               bool   `json:"preferred_address"`
	ResetStreamAt                  bool   `json:"reset_stream_at"`
}

// CloseError describes the error that ended a connection attempt.
type CloseError struct {
	// Type is one of "transport", "application", "idle_timeout",
	// "handshake_timeout", "stateless_reset", "version_negotiation" or
	// "other".
	Type string `json:"type"`

	// Remote is true if the server closed the connection.
	Remote bool `json:"remote"`

	// Code is the QUIC error code for transport and application errors.
	Code uint64 `json:"code,omitempty"`

	// Name is the name of a transport error code, e.g. "CRYPTO_ERROR (0x178)".
	Name string `json:"name,omitempty"`

	// TLSAlert is the TLS alert carried by a CRYPTO_ERROR, e.g.
	// "no application protocol".
	TLSAlert string `json:"tls_alert,omitempty"`

	// Reason is the reason phrase sent with the close.
	Reason string `json:"reason,omitempty"`

	// Message is the full error string.
	Message string `json:"message"`
}
