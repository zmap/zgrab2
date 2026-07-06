#!/usr/bin/env python3
"""
Minimal DRDA (Distributed Relational Database Architecture) server for
integration testing the zgrab2 drda module.

DRDA is the wire protocol spoken by IBM DB2 (and Apache Derby / Informix) on
TCP port 50000. This mock answers a DRDA EXCSAT ("Exchange Server Attributes")
request with a fixed EXCSATRD reply carrying deterministic, EBCDIC-encoded
server attributes, mirroring the response of a real IBM DB2 11.1 server.

Wire layout of a DDM message:
  [length:2][magic:1=0xD0][format:1][correlation-id:2][length2:2][codepoint:2]
  followed by nested parameters, each: [length:2][codepoint:2][data...]
"""

import socket
import struct
import threading
import time

PORT = 50000

# DDM / parameter code points.
CP_EXCSAT = 0x1041
CP_EXCSATRD = 0x1443
CP_EXTNAM = 0x115E
CP_SRVCLSNM = 0x1147
CP_SRVNAM = 0x116D
CP_SRVRLSLV = 0x115A

# Deterministic attributes served to the scanner. These mirror what Shodan/nmap
# surface for a real IBM DB2 11.1 server, minus any per-connection token.
SERVER_CLASS = "QDB2/NT64"   # SRVCLSNM: server platform
INSTANCE_NAME = "DB2"        # SRVNAM: instance name
RELEASE_LEVEL = "SQL11013"   # SRVRLSLV: -> version 11.01.3
EXTERNAL_NAME = "DB2     db2sysc 00000000%FED%Y00"  # EXTNAM

# EBCDIC (code page 500) translation table, ASCII index -> EBCDIC byte. This is
# the inverse of the e2a table used by the zgrab2 drda module.
E2A_HEX = (
    "000102039C09867F978D8E0B0C0D0E0F101112139D8508871819928F1C1D1E1F"
    "80818283840A171B88898A8B8C050607909116939495960498999A9B14159E1A"
    "20A0A1A2A3A4A5A6A7A8D52E3C282B7C26A9AAABACADAEAFB0B121242A293B5E"
    "2D2FB2B3B4B5B6B7B8B9E52C255F3E3FBABBBCBDBEBFC0C1C2603A2340273D22"
    "C3616263646566676869C4C5C6C7C8C9CA6A6B6C6D6E6F707172CBCCCDCECFD0"
    "D17E737475767778797AD2D3D45BD6D7D8D9DADBDCDDDEDFE0E1E2E3E45DE6E7"
    "7B414243444546474849E8E9EAEBECED7D4A4B4C4D4E4F505152EEEFF0F1F2F3"
    "5C9F535455565758595AF4F5F6F7F8F930313233343536373839FAFBFCFDFEFF"
)
_e2a = bytes.fromhex(E2A_HEX)
_a2e = bytearray(256)
for _e in range(256):
    _a2e[_e2a[_e]] = _e


def to_ebcdic(s: str) -> bytes:
    return bytes(_a2e[ord(c)] for c in s)


def make_param(codepoint: int, data: bytes) -> bytes:
    return struct.pack(">HH", len(data) + 4, codepoint) + data


def build_excsatrd() -> bytes:
    params = (
        make_param(CP_EXTNAM, to_ebcdic(EXTERNAL_NAME))
        + make_param(CP_SRVCLSNM, to_ebcdic(SERVER_CLASS))
        + make_param(CP_SRVNAM, to_ebcdic(INSTANCE_NAME))
        + make_param(CP_SRVRLSLV, to_ebcdic(RELEASE_LEVEL))
    )
    total = 10 + len(params)
    # length, magic(0xD0), format, correlation-id, length2, codepoint
    ddm = struct.pack(">HBBHHH", total, 0xD0, 0x03, 1, total - 6, CP_EXCSATRD)
    return ddm + params


EXCSATRD = build_excsatrd()


def read_ddm(conn: socket.socket) -> bytes:
    header = b""
    while len(header) < 2:
        chunk = conn.recv(2 - len(header))
        if not chunk:
            return b""
        header += chunk
    length = struct.unpack(">H", header)[0]
    body = header
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            return b""
        body += chunk
    return body


def handle_client(conn: socket.socket, addr):
    print(f"Connection from {addr}", flush=True)
    try:
        req = read_ddm(conn)
        if len(req) < 10:
            print(f"Short request from {addr}: {req.hex()}", flush=True)
            return
        codepoint = struct.unpack(">H", req[8:10])[0]
        if codepoint != CP_EXCSAT:
            print(
                f"Unexpected request codepoint 0x{codepoint:04x} from {addr}",
                flush=True,
            )
            return
        conn.sendall(EXCSATRD)
        print(f"Served EXCSATRD to {addr}", flush=True)
        # Let the scanner finish reading before we close.
        time.sleep(1)
    except Exception as e:
        print(f"Error handling {addr}: {e}", flush=True)
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", PORT))
        srv.listen(16)
        print(
            f"Listening on port {PORT} (class={SERVER_CLASS}, "
            f"instance={INSTANCE_NAME}, release={RELEASE_LEVEL})",
            flush=True,
        )
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
