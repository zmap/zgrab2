package msmq

import "github.com/zmap/zgrab2/lib/attribution"

// Evidence codes emitted by this module. These are the ONLY vocabulary for
// wire-level evidence in every output mode (compact/standard/debug) --
// human-readable text lives exclusively in EvidenceDescriptions below, for a
// UI/API presentation layer to resolve, not repeated per scanned record.
const (
	EvidenceSignatureValid    attribution.Evidence = "MSMQ_SIGNATURE_VALID"
	EvidencePacketTypeValid   attribution.Evidence = "MSMQ_PACKET_TYPE_VALID"
	EvidencePaddingValid      attribution.Evidence = "MSMQ_PADDING_VALID"
	EvidencePaddingInvalid    attribution.Evidence = "MSMQ_PADDING_INVALID"
	EvidenceServerGuidZero    attribution.Evidence = "MSMQ_SERVER_GUID_ZERO"
	EvidenceServerGuidNonzero attribution.Evidence = "MSMQ_SERVER_GUID_NONZERO"
	EvidenceOSBitSet          attribution.Evidence = "MSMQ_OS_BIT_SET"
	EvidenceOSBitUnset        attribution.Evidence = "MSMQ_OS_BIT_UNSET"
	EvidenceQoSBitSet         attribution.Evidence = "MSMQ_QOS_BIT_SET"
	EvidenceQoSBitUnset       attribution.Evidence = "MSMQ_QOS_BIT_UNSET"
	EvidenceEstablishAccepted attribution.Evidence = "MSMQ_ESTABLISH_ACCEPTED"
	EvidenceEstablishRefused  attribution.Evidence = "MSMQ_ESTABLISH_REFUSED"
	EvidenceResponseValid     attribution.Evidence = "MSMQ_RESPONSE_VALID"
)

// EvidenceDescriptions maps each evidence code above to a human-readable
// sentence. This is the single source of truth for that prose -- no scanned
// record embeds it directly.
var EvidenceDescriptions = map[attribution.Evidence]string{
	EvidenceSignatureValid:    "BaseHeader.Signature matched the required MS-MQQB magic value.",
	EvidencePacketTypeValid:   "InternalHeader.Flags.PT identified a valid EstablishConnection packet.",
	EvidencePaddingValid:      "The response's 512-byte Padding field matched the pattern MS-MQQB mandates for a genuine server response.",
	EvidencePaddingInvalid:    "The response's 512-byte Padding field did not match the pattern MS-MQQB mandates for a genuine server response.",
	EvidenceServerGuidZero:    "The acceptor returned a zero ServerGuid.",
	EvidenceServerGuidNonzero: "The acceptor returned a non-zero ServerGuid, as MS-MQQB requires for a direct-format-name request.",
	EvidenceOSBitSet:          "The acceptor's OperatingSystem field reports itself as a server-class operating system.",
	EvidenceOSBitUnset:        "The acceptor's OperatingSystem field does not report itself as a server-class operating system.",
	EvidenceQoSBitSet:         "The acceptor's OperatingSystem field reports Guaranteed Quality of Service transport support.",
	EvidenceQoSBitUnset:       "The acceptor's OperatingSystem field does not report Guaranteed Quality of Service transport support.",
	EvidenceEstablishAccepted: "The acceptor accepted the EstablishConnection request without requiring authentication.",
	EvidenceEstablishRefused:  "The acceptor refused the EstablishConnection request.",
	EvidenceResponseValid:     "A structurally valid MS-MQQB EstablishConnection response was received.",
}

// FindingDescriptions maps each finding ID this module emits to a
// human-readable title, mirroring EvidenceDescriptions' pattern.
var FindingDescriptions = map[string]string{
	"MSMQ_EXPOSED":             "MSMQ service exposed",
	"MSMQ_ANONYMOUS_HANDSHAKE": "MSMQ accepts an unauthenticated protocol handshake",
}
