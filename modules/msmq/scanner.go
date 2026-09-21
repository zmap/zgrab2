// Package msmq provides a zgrab2 module that scans for Microsoft Message
// Queuing (MSMQ).
// Default port: 1801 (TCP), Microsoft's documented default port for the
// MS-MQQB queue-manager-to-queue-manager protocol.
//
// To keep traffic minimal while remaining accurate, this module performs
// exactly one exchange: it sends an MS-MQQB EstablishConnection Packet (the
// session-initiation request two MSMQ queue managers exchange) and parses
// the EstablishConnection Packet sent back in response. Receiving either an
// accepted or a refused response is a positive, unambiguous identification
// of an MS-MQQB listener -- a refusal still proves the target speaks the
// protocol, it just declined our request (we deliberately omit the queue
// manager GUID, since a scanner has no way to know it in advance).
//
// Note MSMQ is also reachable via RPC through the endpoint mapper (see the
// msrpc module, default port 135) for its separate client/management
// protocols (MS-MQMP/MS-MQMR); this module targets the distinct raw-TCP
// MS-MQQB listener on port 1801.
package msmq

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/attribution"
)

// Flags holds the command-line configuration for the msmq scan module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	// OutputMode selects the result representation: "debug" (default, the
	// full Results shape this module has always produced -- kept as the
	// default so existing consumers, e.g. the correlate tool, keep decoding
	// it unchanged), "standard" (deduplicated structured representation,
	// evidence/finding codes instead of prose, hash-referenced raw evidence
	// instead of inline bytes), or "compact" (target <=1KB/asset for
	// Internet-scale storage -- see CompactResults).
	OutputMode string `long:"output-mode" default:"debug" description:"Result representation: compact, standard, or debug"`
}

// Validate checks that the flags are valid.
func (flags Flags) Validate(_ []string) error {
	switch flags.OutputMode {
	case "compact", "standard", "debug":
		return nil
	default:
		return fmt.Errorf("invalid --output-mode %q: must be compact, standard, or debug", flags.OutputMode)
	}
}

// Results is the output of the msmq scan module.
type Results struct {
	// Protocol names the identified protocol, matching the outer zgrab2
	// ScanResponse.protocol field (which is lowercase "msmq"); this constant
	// "MSMQ" is duplicated here at the request of downstream consumers of
	// this module's result object in isolation.
	Protocol string `json:"protocol"`
	// Detection summarizes whether MS-MQQB was detected, whether the
	// (always-anonymous) connection request was accepted, and how confident
	// this module is that the responder is a genuine, spec-compliant
	// MS-MQQB acceptor.
	Detection attribution.Detection `json:"detection"`
	// Accepted is true if the acceptor's EstablishConnection response did
	// not have the CS (connection refused) flag set.
	Accepted bool `json:"accepted"`
	// ClientGuid/ServerGuid are the queue manager GUIDs echoed back by the
	// acceptor in its EstablishConnectionHeader.
	ClientGuid string `json:"client_guid,omitempty"`
	ServerGuid string `json:"server_guid,omitempty"`
	// TimeStamp is the initiator's timestamp echoed back by the acceptor.
	TimeStamp uint32 `json:"time_stamp"`
	// OperatingSystem is the raw 2-byte EstablishConnectionHeader.OperatingSystem
	// value returned by the acceptor. The low byte is always 0x10 (reserved).
	// The high byte carries the SE/OS/QS flag bits defined in [MS-MQQB]
	// 2.2.3.1 -- confirmed against Microsoft's own worked packet capture
	// ([MS-MQQB] "FRAME 4: Establish Connection Response").
	OperatingSystem uint16 `json:"operating_system,omitempty"`
	// IsSessionMode is true when the SE bit (bit 15, the top bit of the high
	// byte of OperatingSystem) is set in the acceptor's response, indicating
	// the acceptor is operating in session/ping mode (no separate Ping
	// Request will follow).
	IsSessionMode bool `json:"is_session_mode,omitempty"`
	// PaddingMatchesServerPattern is true if the 512-byte
	// EstablishConnectionHeader.Padding field was filled entirely with
	// 0x5A, as MS-MQQB mandates for a response from a genuine acceptor --
	// an additional signal that this is a real MS-MQQB implementation.
	PaddingMatchesServerPattern bool `json:"padding_matches_server_pattern"`
	// Security summarizes security-relevant properties of the exchange.
	Security SecurityInfo `json:"security"`
	// Fingerprint summarizes the response fields useful for distinguishing
	// MS-MQQB implementations/configurations.
	Fingerprint FingerprintInfo `json:"fingerprint"`
	// OSIdentification is always null/unknown at this tier: a single
	// protocol exchange must never assert OS family/version on its own.
	// Populating this requires cross-protocol corroboration (e.g. an
	// NTLM-derived OS version from SMB/RDP on the same host), which is a
	// correlation step built on top of this module's output, not something
	// this module can responsibly claim by itself.
	OSIdentification attribution.OSIdentification `json:"os_identification"`
	// MSMQIdentification is this module's product-level (not OS-level)
	// identification. Version is always nil: [MS-MQQB]'s EstablishConnection
	// packet has no QueueManagerVersion field to read -- see
	// VersionIdentification.
	MSMQIdentification MSMQIdentification `json:"msmq_identification"`
	// VersionIdentification explicitly reports that exact
	// MSMQ/QueueManager version information is not obtainable from this
	// exchange, rather than silently omitting it or -- worse -- guessing.
	VersionIdentification attribution.VersionIdentification `json:"version_identification"`
	// VulnerabilityAssessment grades exposure risk from what this exchange
	// can actually prove (see assessVulnerability), never naming a specific
	// CVE without exact version evidence this exchange cannot provide.
	VulnerabilityAssessment attribution.VulnerabilityAssessment `json:"vulnerability_assessment"`
	// SecurityAssessment grades each level of the graduated anonymous-access
	// model this module can and cannot evaluate (see SecurityAssessment).
	SecurityAssessment SecurityAssessment `json:"security_assessment"`
	// SecurityPosture is a flat, correlation-engine-friendly summary of
	// SecurityAssessment's three status values.
	SecurityPosture SecurityPosture `json:"security_posture"`
	// Findings lists security-relevant observations about this target,
	// derived from the fields above.
	Findings []attribution.Finding `json:"findings,omitempty"`
	// Raw is the hex-encoded response packet, included when --verbose is set.
	// Kept for backward compatibility; RawEvidence below carries the same
	// availability/hash/length metadata that standard/compact modes expose
	// without the inline bytes.
	Raw string `json:"raw,omitempty"`
	// RawEvidence reports whether/how the raw response is available, without
	// requiring every record to carry the ~1.1KB inline blob. Available/
	// SHA256/Length are populated whenever --verbose captured a response
	// (i.e. whenever Raw is non-empty); Inline is true here since debug mode
	// also keeps the legacy inline Raw field.
	RawEvidence RawEvidenceInfo `json:"raw_evidence"`
}

// MSMQIdentification is module-local product-version identification
// (distinct from OS identification, see Results.OSIdentification).
type MSMQIdentification struct {
	// Version is always nil: [MS-MQQB]'s EstablishConnection packet has no
	// QueueManagerVersion field.
	Version *string `json:"version"`
	// Confidence grades how confident this module is that the responder is
	// a genuine, spec-compliant MS-MQQB implementation -- not a version
	// confidence, since there is no version to be confident about.
	Confidence attribution.Confidence `json:"confidence"`
	Evidence   []attribution.Evidence `json:"evidence,omitempty"`
}

// SecurityInfo reports security-relevant properties of the EstablishConnection
// exchange. The MS-MQQB EstablishConnection Packet ([MS-MQQB] 2.2.3) has no
// field for authentication or encryption of any kind -- AuthenticationObserved
// and EncryptionObserved are therefore always false, not because the target
// necessarily lacks either, but because this single-packet exchange has no
// capability to negotiate or reveal them either way. Note the deliberate
// distinction this module maintains: AuthenticationObserved=false means only
// that no authentication step was present *in this exchange* to observe --
// it is never promoted to a claim that authentication is disabled on the
// target generally.
type SecurityInfo struct {
	// AuthenticationObserved is always false: this exchange has no
	// authentication step to observe.
	AuthenticationObserved bool `json:"authentication_observed"`
	// EncryptionObserved is always false: MS-MQQB's raw TCP EstablishConnection
	// exchange has no transport-encryption negotiation.
	EncryptionObserved bool `json:"encryption_observed"`
	// AnonymousHandshake is a first-class security posture signal: whether
	// this specific target's acceptor exhibited anonymous-handshake-accepting
	// behavior (Level 1 of the graduated anonymous-access model -- see
	// SecurityAssessment). This is a target-behavior fact (it varies with
	// Accepted), not a statement about this module's own probe design (this
	// module always requests anonymously, by direct format name with zero
	// ClientGuid/ServerGuid per [MS-MQQB] 2.2.3.1, since a scanner has no
	// queue manager GUID to present in advance -- that fact alone doesn't
	// belong here since it's true regardless of what the target does).
	AnonymousHandshake AnonymousHandshakeInfo `json:"anonymous_handshake"`
}

// AnonymousHandshakeInfo reports Level 1 of the graduated anonymous-access
// model: whether the target's EstablishConnection response indicates it
// accepted our anonymous (unauthenticated) connection request. It says
// nothing about queue, message, or administrative access (Levels 2/3) --
// see SecurityAssessment for the explicit statuses covering those.
type AnonymousHandshakeInfo struct {
	// Detected is true iff the acceptor accepted the anonymous
	// EstablishConnection request (mirrors Results.Accepted).
	Detected bool `json:"detected"`
	// Confidence grades how confident this module is that Detected reflects
	// genuine MS-MQQB behavior, not an anomalous/non-compliant responder
	// (mirrors Detection.Confidence).
	Confidence attribution.Confidence `json:"confidence"`
	// Scope is a constant, explicit boundary marker: this signal covers the
	// protocol handshake only.
	Scope    string                 `json:"scope"`
	Evidence []attribution.Evidence `json:"evidence"`
}

// anonymousHandshakeScope is the constant Scope value for
// AnonymousHandshakeInfo, naming the exact boundary of what this module
// observes -- never queue, message, or administrative access.
const anonymousHandshakeScope = "protocol_handshake_only"

// SecurityAssessment grades each level of the graduated anonymous-access
// model this module can and cannot evaluate. Level 1 (AnonymousHandshake) is
// the only level this passive, single-exchange probe can actually observe;
// Levels 2/3 are always "not_tested" -- this module never creates queues,
// enumerates queues, sends/reads messages, tests credentials, or performs
// any other state-changing or resource-access operation.
type SecurityAssessment struct {
	AnonymousHandshake      AnonymousHandshakeAssessment `json:"anonymous_handshake"`
	AnonymousProtocolAccess UntestedAccessAssessment     `json:"anonymous_protocol_access"`
	AnonymousResourceAccess UntestedAccessAssessment     `json:"anonymous_resource_access"`
}

// AnonymousHandshakeAssessment grades Level 1 specifically. Severity is
// always "informational": an accepted anonymous handshake, by itself, is a
// posture observation, not a confirmed vulnerability -- see
// Results.VulnerabilityAssessment for why this module never escalates a
// handshake-only observation into a higher-severity finding.
type AnonymousHandshakeAssessment struct {
	// Status is "confirmed" when the acceptor accepted the anonymous
	// handshake, "not_confirmed" when it was refused (or the responder was
	// too anomalous to trust -- see Confidence).
	Status     string                 `json:"status"`
	Severity   string                 `json:"severity"`
	Confidence attribution.Confidence `json:"confidence"`
	// Impact states plainly what Status="confirmed" does and does not mean.
	Impact string `json:"impact"`
	// Limitation states explicitly that this probe never goes beyond the
	// handshake -- present regardless of Status, since it describes what
	// this module is capable of proving in general, not just this result.
	Limitation string `json:"limitation"`
}

// UntestedAccessAssessment represents a graduated-access level this module
// never attempts to evaluate (Levels 2/3: anonymous protocol/resource
// access). Status is always "not_tested" and Confidence is always "none" --
// distinct from "unknown" (which would imply an attempt was made and the
// result was inconclusive).
type UntestedAccessAssessment struct {
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
}

// untestedAccessAssessment is the constant value for both
// AnonymousProtocolAccess and AnonymousResourceAccess: this module performs
// no queue creation, queue enumeration, message send/read, or credential
// testing of any kind, so these are always "not_tested"/"none", never
// varying by response.
var untestedAccessAssessment = UntestedAccessAssessment{Status: "not_tested", Confidence: "none"}

// SecurityPosture is a flat, correlation-engine-friendly summary of
// SecurityAssessment's three status values, so a downstream correlator can
// read posture without re-deriving it from the richer nested structure.
type SecurityPosture struct {
	AnonymousHandshake      string `json:"anonymous_handshake"`
	AnonymousProtocolAccess string `json:"anonymous_protocol_access"`
	AnonymousResourceAccess string `json:"anonymous_resource_access"`
}

// FingerprintInfo collects the EstablishConnection response fields useful for
// fingerprinting the acceptor.
type FingerprintInfo struct {
	// OperatingSystem is the raw EstablishConnectionHeader.OperatingSystem
	// value, duplicated here from Results.OperatingSystem for convenience.
	OperatingSystem uint16 `json:"operating_system"`
	// OperatingSystemRaw is the same value as OperatingSystem, named to match
	// the operating_system_hex field below and to be explicit that this is
	// an unparsed wire value, not an OS identification.
	OperatingSystemRaw uint16 `json:"operating_system_raw"`
	// OperatingSystemHex is OperatingSystemRaw formatted as a 0x-prefixed
	// hex string (e.g. "0x1080"), for easier manual bit inspection.
	OperatingSystemHex string `json:"operating_system_hex"`
	// TimeStamp mirrors Results.TimeStamp.
	TimeStamp uint32 `json:"time_stamp"`
	// SessionMode mirrors Results.IsSessionMode.
	SessionMode bool `json:"session_mode"`
	// PaddingMatchesServerPattern mirrors Results.PaddingMatchesServerPattern.
	PaddingMatchesServerPattern bool `json:"padding_matches_server_pattern"`
	// ClientGuidZero/ServerGuidZero report whether the response's ClientGuid/
	// ServerGuid ([MS-MQQB] 2.2.3.1) came back as the zero GUID. ClientGuidZero
	// is expected to always be true, since the acceptor echoes back whatever
	// ClientGuid the initiator sent (always zero for this module). ServerGuidZero
	// is a genuine signal: per spec, an acceptor handling a direct-format-name
	// request MUST return its own (non-zero) queue manager GUID here, so a zero
	// value indicates a non-compliant or unconfigured/unidentified queue manager.
	ClientGuidZero bool `json:"client_guid_zero"`
	ServerGuidZero bool `json:"server_guid_zero"`
	// AcceptorIsServerOS decodes the OS bit ([MS-MQQB] 2.2.3.1, field B): true
	// if the acceptor reports itself as running a server-class operating
	// system.
	AcceptorIsServerOS bool `json:"acceptor_is_server_os"`
	// AcceptorSupportsGQoS decodes the QS bit ([MS-MQQB] 2.2.3.1, field C):
	// true if the acceptor's underlying transport supports Guaranteed Quality
	// of Service ([RFC2212]).
	AcceptorSupportsGQoS bool `json:"acceptor_supports_gqos"`
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// NewModule returns a new msmq module.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"msmq",
		"Probe for Microsoft Message Queuing (MSMQ) queue managers",
		"Send an MS-MQQB EstablishConnection request and parse the EstablishConnection reply, identifying MSMQ queue-manager-to-queue-manager (Binary Reliable Messaging Protocol) listeners with a single request/response exchange",
		1801,
	)
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// Scan connects to the target (default port 1801), sends a single MS-MQQB
// EstablishConnection request, and parses the EstablishConnection reply.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not dial target %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	// A zero ClientGuid/ServerGuid and a zero TimeStamp are all that's
	// needed: ServerGuid == 0 is the documented "direct format name" request
	// form, since a scanner has no way to know the target's real queue
	// manager GUID up front.
	var clientGUID, serverGUID [16]byte
	req := buildEstablishConnection(clientGUID, serverGUID, 0)
	if _, err = conn.Write(req); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not send EstablishConnection request to %s: %w", target.String(), err)
	}

	resp := make([]byte, establishConnectionPacketLen)
	if _, err = io.ReadFull(conn, resp); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not read EstablishConnection reply from %s: %w", target.String(), err)
	}

	parsed, err := parseEstablishConnection(resp)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("reply from %s was not a valid MS-MQQB EstablishConnection packet: %w", target.String(), err)
	}

	accepted := !parsed.Refused
	clientGUIDZero := parsed.ClientGUID == [16]byte{}
	serverGUIDZero := parsed.ServerGUID == [16]byte{}
	confidence, msmqEvidence := assessConfidence(parsed, serverGUIDZero)
	anonymousHandshake := buildAnonymousHandshakeInfo(accepted, confidence, parsed)
	securityAssessment := buildSecurityAssessment(accepted, confidence)

	results := &Results{
		Protocol: "MSMQ",
		Detection: attribution.Detection{
			Detected:   true,
			Accepted:   accepted,
			Confidence: confidence,
		},
		Accepted:                    accepted,
		ClientGuid:                  formatGUID(parsed.ClientGUID),
		ServerGuid:                  formatGUID(parsed.ServerGUID),
		TimeStamp:                   parsed.TimeStamp,
		OperatingSystem:             parsed.OperatingSystem,
		IsSessionMode:               parsed.OperatingSystem&ecOSFlagSE != 0,
		PaddingMatchesServerPattern: parsed.PaddingMatchesResponse,
		Security: SecurityInfo{
			AuthenticationObserved: false,
			EncryptionObserved:     false,
			AnonymousHandshake:     anonymousHandshake,
		},
		Fingerprint: FingerprintInfo{
			OperatingSystem:             parsed.OperatingSystem,
			OperatingSystemRaw:          parsed.OperatingSystem,
			OperatingSystemHex:          fmt.Sprintf("0x%04x", parsed.OperatingSystem),
			TimeStamp:                   parsed.TimeStamp,
			SessionMode:                 parsed.OperatingSystem&ecOSFlagSE != 0,
			PaddingMatchesServerPattern: parsed.PaddingMatchesResponse,
			ClientGuidZero:              clientGUIDZero,
			ServerGuidZero:              serverGUIDZero,
			AcceptorIsServerOS:          parsed.IsServerOS,
			AcceptorSupportsGQoS:        parsed.SupportsGQoS,
		},
		OSIdentification: attribution.OSIdentification{
			FamilyConfidence: attribution.ConfidenceUnknown,
			Confidence:       attribution.ConfidenceUnknown,
			Evidence:         buildOSEvidence(parsed),
		},
		MSMQIdentification: MSMQIdentification{
			Confidence: confidence,
			Evidence:   msmqEvidence,
		},
		VersionIdentification: attribution.VersionIdentification{
			Status: attribution.VersionNotAvailablePreAuth,
		},
		VulnerabilityAssessment: assessVulnerability(accepted, confidence),
		SecurityAssessment:      securityAssessment,
		SecurityPosture: SecurityPosture{
			AnonymousHandshake:      securityAssessment.AnonymousHandshake.Status,
			AnonymousProtocolAccess: securityAssessment.AnonymousProtocolAccess.Status,
			AnonymousResourceAccess: securityAssessment.AnonymousResourceAccess.Status,
		},
		Findings: []attribution.Finding{
			{
				ID:         "MSMQ_EXPOSED",
				Severity:   "medium",
				Confidence: attribution.ConfidenceHigh,
			},
		},
	}
	if accepted {
		// This module always requests a connection anonymously (zero
		// ClientGuid/ServerGuid); an accepted response means the acceptor
		// completed Level 1 of the graduated anonymous-access model (see
		// SecurityAssessment) without requiring authentication. This finding
		// is deliberately informational-severity: it reports only that the
		// handshake succeeded, never that queue, message, or administrative
		// access was established. Confidence mirrors the same assessed
		// confidence as everything else -- never hardcoded high regardless
		// of how trustworthy the responder actually is.
		results.Findings = append(results.Findings, attribution.Finding{
			ID:         "MSMQ_ANONYMOUS_HANDSHAKE",
			Severity:   "informational",
			Confidence: confidence,
		})
	}
	if scanner.config.Verbose {
		results.Raw = hex.EncodeToString(resp)
	}
	results.RawEvidence = rawEvidence(results.Raw, true)

	// Both an accepted and a refused EstablishConnection response positively
	// identify an MS-MQQB listener -- a refusal merely means our (necessarily
	// GUID-less) request was declined.
	switch scanner.config.OutputMode {
	case "compact":
		return zgrab2.SCAN_SUCCESS, newCompactResults(results), nil
	case "standard":
		return zgrab2.SCAN_SUCCESS, newStandardResults(results), nil
	default: // "debug"
		return zgrab2.SCAN_SUCCESS, results, nil
	}
}
