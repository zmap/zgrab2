# zschema sub-schema for zgrab2's http module
# Registers zgrab2-http globally, and http with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

# lib/http/header.go: knownHeaders
http_known_headers = [
    "accept",
    "accept_charset",
    "accept_encoding",
    "accept_language",
    "accept_patch",
    "accept_ranges",
    "access_control_allow_origin",
    "age",
    "allow",
    "alt_svc",
    "alternate_protocol",
    "authorization",
    "cache_control",
    "connection",
    "content_disposition",
    "content_encoding",
    "content_language",
    "content_length",
    "content_location",
    "content_md5",
    "content_range",
    "content_security_policy",
    "content_type",
    "cookie",
    "date",
    "etag",
    "expect",
    "expires",
    "from",
    "host",
    "if_match",
    "if_modified_since",
    "if_none_match",
    "if_unmodified_since",
    "last_modified",
    "link",
    "location",
    "max_forwards",
    "p3p",
    "pragma",
    "proxy_agent",
    "proxy_authenticate",
    "proxy_authorization",
    "public_key_pins",
    "range",
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
    "user_agent",
    "vary",
    "via",
    "warning",
    "www_authenticate",
    "x_content_duration",
    "x_content_security_policy",
    "x_content_type_options",
    "x_forwarded_for",
    "x_frame_options",
    "x_powered_by",
    "x_real_ip",
    "x_ua_compatible",
    "x_webkit_csp",
    "x_xss_protection",
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

# modules/http.go: HTTPResults
http_scan_response = SubRecord({
    "result": SubRecord({
        "connect_request": http_request,
        "connect_response": http_response,
        "response": http_response_full,
        "redirect_response_chain": ListOf(http_response_full),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-http", http_scan_response)

zgrab2.register_scan_response_type("http", http_scan_response)
