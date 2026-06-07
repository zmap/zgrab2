#!/usr/bin/env python3
"""
Minimal Check Point Firewall-1 topology protocol server for integration testing.

Protocol (port 264 TCP):
  Client → Server: 8-byte identification probe (\x51\x00\x00\x00\x00\x00\x00\x21)
  Server → Client: 4-byte ACK (\x59\x00\x00\x00)
  Client → Server: topology request (\x00\x00\x00\x0bsecuremote\x00)
  Server → Client: [4-byte length][null-terminated DN][4-byte cipher count][cipher entries...]

Each cipher entry: [4-byte length including \x00][name\x00]
"""

import socket
import struct
import threading
import os
import time

HOST = "fw1.example.com"
DOMAIN = "smartcenter.example.com"
OBJECT_SUFFIX = "oo2u8w"
CIPHER_SUITES = [
    "none",
    "sslca_clear",
    "sslca",
    "sslca_comp",
    "sslca_rc4",
    "sslca_rc4_comp",
    "asym_sslca",
    "asym_sslca_comp",
    "asym_sslca_rc4",
    "asym_sslca_rc4_comp",
]
PORT = 264

# https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/checkpoint_hostname.rb#L59
PROBE1 = b"\x51\x00\x00\x00" + b"\x00\x00\x00\x21"
ACK1 = b"\x59\x00\x00\x00"
PROBE2 = b"\x00\x00\x00\x0bsecuremote\x00"
ACK2 = (
    b"\x00\x00\x00$CN=fw1.example.com,O=smartcenter.example.com..oo2u8w\x00\x00\x00\x00\x0c\x00\x00\x00\x05"
    b"none\x00\x00\x00\x00\x06sslca\x00\x00\x00\x00\x0bsslca_comp\x00\x00\x00\x00\nsslca_rc4\x00\x00\x00"
    b"\x00\x0fsslca_rc4_comp\x00\x00\x00\x00\x04ssl\x00\x00\x00\x00\x05fwa1\x00\x00\x00\x00\x05fwn1\x00\x00"
    b"\x00\x00\x0basym_sslca\x00\x00\x00\x00\x10asym_sslca_comp\x00\x00\x00\x00\x0fasym_sslca_rc4\x00\x00\x00"
    b"\x00\x14asym_sslca_rc4_comp\x00"
)


def handle_client(conn: socket.socket, addr):
    print(f"Connection from {addr}", flush=True)
    try:
        data = b""
        while len(data) < len(PROBE1):
            chunk = conn.recv(len(PROBE1) - len(data))
            if not chunk:
                return
            data += chunk

        if data != PROBE1:
            print(f"Unexpected probe from {addr}: {data.hex()}", flush=True)
            return

        conn.sendall(ACK1)

        data = b""
        while len(data) < len(PROBE2):
            chunk = conn.recv(len(PROBE2) - len(data))
            if not chunk:
                return
            data += chunk

        if data != PROBE2:
            print(f"Unexpected topology request from {addr}: {data.hex()}", flush=True)
            return

        conn.sendall(ACK2)
        print(
            f"Served topology to {addr}: CN={HOST},O={DOMAIN}.{OBJECT_SUFFIX}",
            flush=True,
        )
        # Let the scanner read all there is to read and time out
        time.sleep(10)
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
            f"Listening on port {PORT} (CN={HOST}, O={DOMAIN}.{OBJECT_SUFFIX})",
            flush=True,
        )
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
