# zschema sub-schema for zgrab2's ipp module
# Registers zgrab2-ipp globally, and ipp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
import zgrab2

# TODO: Eventually re-introduce (non-cicular) dependency on HTTP zgrab2 schema
# lib/http/header.go: knownHeaders
http_known_headers = [
    "access_control_allow_origin",
    "accept_patch",
    "accept_ranges",
    "age",
    "allow",
    "alt_svc",
    "alternate_protocol",
    "cache_control",
    "connection",
    "content_disposition",
    "content_encoding",
    "content_language",
    "content_length",
    "content_location",
    "content_md5",
    "content_range",
    "content_type",
    "expires",
    "last_modified",
    "link",
    "location",
    "p3p",
    "pragma",
    "proxy_agent",
    "proxy_authenticate",
    "public_key_pins",
    "referer",
    "refresh",
    "retry_after",
    "server",
    "set_cookie",
    "status",
    "strict_transport_security",
    "trailer",
    "transfer_encoding",
    "upgrade",
    "vary",
    "via",
    "warning",
    "www_authenticate",
    "x_frame_options",
    "x_xss_protection",
    "content_security_policy",
    "x_content_security_policy",
    "x_webkit_csp",
    "x_content_type_options",
    "x_powered_by",
    "x_ua_compatible",
    "x_content_duration",
    "x_real_ip",
    "x_forwarded_for",
]

http_unknown_headers = ListOf(SubRecord({
    "key": String(),
    "value": ListOf(String())
}))

_http_headers = dict(
    (header_name, ListOf(String()))
    for header_name in http_known_headers
)
_http_headers["unknown"] = http_unknown_headers

# Format from the custom JSON Marshaller in lib/http/header.go
http_headers = SubRecord(_http_headers)

# net.url: type Values map[string][]string
http_form_values = SubRecord({})  # TODO FIXME: unconstrained dict

# lib/http/request.go: URLWrapper
http_url_wrapper = SubRecord({
    "scheme": String(),
    "opaque": String(),
    "host": String(),
    "path": String(),
    "raw_path": String(),
    "raw_query": String(),
    "fragment": String()
})

# modules/http.go: HTTPRequest
http_request = SubRecord({
    "method": String(),
    "endpoint": String(),
    "user_agent": String(),
    "body": String()
})

# modules/http.go: HTTPResponse
http_response = SubRecord({
    "version_major": Signed32BitInteger(),
    "version_minor": Signed32BitInteger(),
    "status_code": Signed32BitInteger(),
    "status_line": String(),
    "headers": http_headers,
    "body": String(),
    "body_sha256": String()
})

# lib/http/request.go: http.Request
http_request_full = SubRecord({
    "url": http_url_wrapper,
    "method": String(),
    "headers":  http_headers,
    "body": String(),
    "content_length": Signed64BitInteger(),
    "transfer_encoding": ListOf(String()),
    "close": Boolean(),
    "host": String(),
    "form": http_form_values,
    "post_form": http_form_values,
    "multipart_form": http_form_values,
    "trailers": http_headers,
    # The new field tls_log contains the zgrab2 TLS logs.
    "tls_log": zgrab2.tls_log
})

# lib/http/response.go: http.Response
http_response_full = SubRecord({
    "status_line": String(),
    "status_code": Unsigned32BitInteger(),
    # lib/http/protocol.go: http.Protocol
    "protocol": SubRecord({
        "name": String(),
        "major": Unsigned32BitInteger(),
        "minor": Unsigned32BitInteger(),
    }),
    "headers": http_headers,
    "body": String(),
    "body_sha256": Binary(),
    "content_length": Signed64BitInteger(),
    "transfer_encoding": ListOf(String()),
    "trailers": http_headers,
    "request": http_request_full
})

# TODO: Determine whether value-tag types with same underlying form should have a different name in this mapping
ipp_attribute_value = SubRecord({
    "raw": Binary(),
    "integer": Signed32BitInteger(),
    "boolean": Boolean(),
    "enum": String(),
    # TODO: Determine appropriate type for octetString w/o specified format
    "octetString": Binary(),
    "dateTime": DateTime(),
    # TODO: Determine appropriate type for resolution
    "resolution": Binary(),
    # TODO: Determine appropriate type for range of Integers (probably {min, max} pair)
    "rangeOfInteger": Binary(),
    # TODO: Determine appropriate type for beginning of attribute collection
    "begCollection": Binary(),
    "textWithLanguage": String(),
    "nameWithLanguage": String(),
    # TODO: Determine appropriate type for end of attribute collection
    "endCollection": Binary(),
    "textWithoutLanguage": String(),
    "nameWithoutLanguage": String(),
    "keyword": String(),
    "uri": String(),
    "uriScheme": String(),
    "charset": String(),
    "naturalLanguage": String(),
    "mimeMediaType": String(),
    "memberAttrName": String(),
})

ipp_attribute = SubRecord({
    "name": String(),
    "values": ListOf(ipp_attribute_value),
    "tag": Binary(),
})

ipp_scan_response = SubRecord({
    "result": SubRecord({
        "version_major": Signed8BitInteger(),
        "version_minor": Signed8BitInteger(),
        "version_string": String(),
        "cups_version": String(),
        "attributes": ListOf(ipp_attribute),
        "attr_cups_version": String(),
        "attr_ipp_versions": ListOf(String()),
        "attr_printer_uris": ListOf(String()),
        "response": http_response_full,
        "cups_response": http_response_full,
        "tls": zgrab2.tls_log,
        "redirect_response_chain": ListOf(http_response_full),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-ipp", ipp_scan_response)

zgrab2.register_scan_response_type("ipp", ipp_scan_response)
