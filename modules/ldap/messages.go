package ldap

import (
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// LDAP protocol constants
const (
	// Application-level tags for LDAP messages
	ApplicationBindRequest       = 0
	ApplicationBindResponse      = 1
	ApplicationSearchRequest     = 3
	ApplicationSearchResultEntry = 4
	ApplicationSearchResultDone  = 5
	ApplicationExtendedRequest   = 23
	ApplicationExtendedResponse  = 24

	// Search scope
	ScopeBaseObject = 0

	// Deref aliases
	NeverDerefAliases = 0

	// Filter tags
	FilterPresent = 7

	// STARTTLS OID
	OIDStartTLS = "1.3.6.1.4.1.1466.20037"
)

// buildSearchRequest creates a BER-encoded LDAP SearchRequest for the Root DSE.
// Root DSE search: base DN "", scope base, filter (objectClass=*), all attributes.
func buildSearchRequest(messageID int64) *ber.Packet {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")

	// Message ID
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))

	// SearchRequest (application 3, constructed)
	searchReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchRequest, nil, "SearchRequest")

	// Base DN (empty string for Root DSE)
	searchReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "BaseObject"))

	// Scope: baseObject (0)
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ScopeBaseObject), "Scope"))

	// DerefAliases: neverDerefAliases (0)
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(NeverDerefAliases), "DerefAliases"))

	// SizeLimit: 0 (no limit)
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "SizeLimit"))

	// TimeLimit: 0 (no limit)
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "TimeLimit"))

	// TypesOnly: false
	searchReq.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "TypesOnly"))

	// Filter: (objectClass=*) — a "present" filter for objectClass
	searchReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, FilterPresent, "objectClass", "Filter: Present(objectClass)"))

	// "*" selects user attributes; "+" also selects operational Root DSE attributes.
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, selector := range []string{"*", "+"} {
		attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, selector, "AttributeSelector"))
	}
	searchReq.AppendChild(attributes)

	envelope.AppendChild(searchReq)
	return envelope
}

// buildExtendedRequest creates a BER-encoded LDAP ExtendedRequest (used for STARTTLS).
func buildExtendedRequest(messageID int64, oid string) *ber.Packet {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")

	// Message ID
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))

	// ExtendedRequest (application 23, constructed)
	extReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "ExtendedRequest")

	// Request Name (context 0, primitive) — the OID
	extReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, oid, "RequestName"))

	envelope.AppendChild(extReq)
	return envelope
}

// readLDAPMessage reads a single BER-encoded LDAP message from the connection.
func readLDAPMessage(conn deadlineConn) (*ber.Packet, error) {
	packet, err := ber.ReadPacket(conn)
	if err != nil {
		return nil, fmt.Errorf("error reading LDAP message: %w", err)
	}

	// An LDAP message is a SEQUENCE containing at least a messageID and a protocol op
	if len(packet.Children) < 2 {
		return nil, fmt.Errorf("invalid LDAP message: expected at least 2 children, got %d", len(packet.Children))
	}

	return packet, nil
}

// getMessageTag returns the application tag of the protocol operation in an LDAP message.
func getMessageTag(packet *ber.Packet) ber.Tag {
	if len(packet.Children) < 2 {
		return 0
	}
	return packet.Children[1].Tag
}

// getResultCode extracts the result code from an LDAP result message (BindResponse, SearchResultDone, ExtendedResponse).
func getResultCode(packet *ber.Packet) (int64, error) {
	if len(packet.Children) < 2 {
		return -1, errors.New("invalid LDAP message")
	}
	resultMsg := packet.Children[1]
	if len(resultMsg.Children) < 1 {
		return -1, errors.New("invalid LDAP result message: no children")
	}
	return forceInt64(resultMsg.Children[0])
}

// parseSearchResultEntry extracts attribute name-value pairs from a SearchResultEntry message.
func parseSearchResultEntry(packet *ber.Packet) (map[string][]string, error) {
	if len(packet.Children) < 2 {
		return nil, errors.New("invalid LDAP message")
	}

	entry := packet.Children[1]
	// SearchResultEntry: SEQUENCE { objectName, attributes }
	if len(entry.Children) < 2 {
		return nil, fmt.Errorf("invalid SearchResultEntry: expected at least 2 children, got %d", len(entry.Children))
	}

	attrs := make(map[string][]string)
	attrList := entry.Children[1] // PartialAttributeList (SEQUENCE OF)

	for _, attrSeq := range attrList.Children {
		// Each attribute is: SEQUENCE { type (OCTET STRING), vals (SET OF OCTET STRING) }
		if len(attrSeq.Children) < 2 {
			continue
		}
		attrName := string(attrSeq.Children[0].ByteValue)
		valSet := attrSeq.Children[1]
		var values []string
		for _, val := range valSet.Children {
			values = append(values, string(val.ByteValue))
		}
		attrs[attrName] = values
	}

	return attrs, nil
}

// forceInt64 reads an integer value from a BER packet.
func forceInt64(p *ber.Packet) (int64, error) {
	if p.Value == nil {
		// Try to decode the raw bytes
		val, err := ber.ParseInt64(p.ByteValue)
		if err != nil {
			return 0, fmt.Errorf("could not parse integer: %w", err)
		}
		return val, nil
	}
	switch v := p.Value.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case uint64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("unexpected integer type %T", v)
	}
}

// deadlineConn is a minimal interface for a connection that supports reading LDAP messages.
// Both net.Conn and zgrab2.TLSConnection satisfy this.
type deadlineConn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
}
