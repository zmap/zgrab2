# Banner probe templates

The `banner` module can expand probe data after opening each connection. This
mode is opt-in so existing probes remain unchanged:

```shell
zgrab2 banner --expand-probe --probe-file request.tpl
```

The template syntax and field byte encodings match ZMap's UDP probe templates:

| Field | Expansion |
| --- | --- |
| `${SADDR}`, `${DADDR}` | Source and destination IP addresses as text |
| `${SPORT}`, `${DPORT}` | Source and destination ports as text |
| `${SADDR_N}`, `${DADDR_N}` | IPv4 source and destination addresses in network byte order |
| `${SPORT_N}`, `${DPORT_N}` | Source and destination ports in network byte order |
| `${RAND_BYTE=n}` | `n` random bytes |
| `${RAND_DIGIT=n}` | `n` random ASCII digits |
| `${RAND_ALPHA=n}` | `n` random mixed-case ASCII letters |
| `${RAND_ALPHANUM=n}` | `n` random ASCII letters or digits |
| `${HEX=value}` | Hexadecimal `value` decoded to bytes |
| `${UNIXTIME_SEC}` | Unix seconds in 32-bit network byte order |
| `${UNIXTIME_USEC}` | Microseconds within the current second in 32-bit network byte order |
| `${NTP_TIMESTAMP}` | RFC 5905 64-bit NTP timestamp in network byte order |

Unknown fields are sent literally, matching ZMap. The `_N` address fields are
defined by ZMap as four-byte IPv4 values and therefore fail on IPv6
connections; `${SADDR}` and `${DADDR}` support IPv6 text.

For example, this template:

```text
OPTIONS sip:${RAND_ALPHA=8}@${DADDR} SIP/2.0
Via: SIP/2.0/TCP ${SADDR}:${SPORT}
```

is expanded using the actual local and remote socket addresses before the probe
is sent. Expansion applies equally to `--probe` and `--probe-file`.
