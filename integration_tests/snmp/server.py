#!/usr/bin/env python3
import os
import socket


def tlv(tag, value):
    return bytes((tag, len(value))) + value


response = tlv(
    0x30,
    tlv(0x02, b"\x00")
    + tlv(0x04, b"public")
    + tlv(
        0xA2,
        tlv(0x02, b"\x01")
        + tlv(0x02, b"\x00")
        + tlv(0x02, b"\x00")
        + tlv(0x30, b""),
    ),
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", int(os.getenv("SNMP_PORT", "161"))))


def request_version(data):
    if len(data) < 5 or data[0] != 0x30:
        return None
    length_octets = data[1] & 0x7F if data[1] & 0x80 else 0
    offset = 2 + length_octets
    if len(data) < offset + 3 or data[offset : offset + 2] != b"\x02\x01":
        return None
    return data[offset + 2]


while True:
    data, address = sock.recvfrom(65535)
    if request_version(data) == 0:
        sock.sendto(response, address)
