package ldap

import (
	"bytes"
	"reflect"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestRootDSEAttributeSelection(t *testing.T) {
	packet, err := ber.ReadPacket(bytes.NewReader(buildSearchRequest(2).Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	search := packet.Children[1]
	if search.Tag != ApplicationSearchRequest || len(search.Children) != 8 {
		t.Fatalf("unexpected search request: %+v", search)
	}
	selectors := make([]string, 0, len(search.Children[7].Children))
	for _, attribute := range search.Children[7].Children {
		if attribute.ClassType != ber.ClassUniversal || attribute.Tag != ber.TagOctetString {
			t.Fatalf("invalid attribute selector: %+v", attribute)
		}
		selectors = append(selectors, string(attribute.ByteValue))
	}
	if !reflect.DeepEqual(selectors, []string{"*", "+"}) {
		t.Fatalf("attribute selectors = %v, want user (*) and operational (+) attributes", selectors)
	}
}

func TestRootDSEOperationalAttributes(t *testing.T) {
	want := map[string][]string{
		"objectClass":          {"top", "OpenLDAProotDSE"},
		"namingContexts":       {"dc=example,dc=com"},
		"supportedControl":     {"1.2.840.113556.1.4.319"},
		"supportedExtension":   {OIDStartTLS},
		"supportedLDAPVersion": {"3"},
		"subschemaSubentry":    {"cn=Subschema"},
	}
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	for name, values := range want {
		attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		for _, value := range values {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
		}
		attribute.AppendChild(set)
		attributes.AppendChild(attribute)
	}
	entry.AppendChild(attributes)
	message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 2, ""))
	message.AppendChild(entry)
	packet, err := readLDAPMessage(bytes.NewBuffer(message.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := parseSearchResultEntry(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(attrs, want) {
		t.Fatalf("attributes = %v, want %v", attrs, want)
	}
	var result ScanResults
	populateResults(&result, attrs)
	if !reflect.DeepEqual(result.NamingContexts, want["namingContexts"]) ||
		!reflect.DeepEqual(result.SupportedControl, want["supportedControl"]) ||
		!reflect.DeepEqual(result.SupportedLDAPVersion, want["supportedLDAPVersion"]) ||
		result.SubschemaSubentry != "cn=Subschema" ||
		!serverSupportsStartTLS(&result) ||
		!reflect.DeepEqual(result.OtherAttributes["objectClass"], want["objectClass"]) {
		t.Fatalf("operational attributes not collected correctly: %+v", result)
	}
}
