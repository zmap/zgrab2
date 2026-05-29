#!/usr/bin/env python3
"""
Minimal Check Point Firewall-1 topology protocol server for integration testing.

Protocol (port 264 TCP):
  Client → Server: 8-byte identification probe (\x51\x00\x00\x00\x00\x00\x00\x21)
  Server → Client: 8-byte ACK starting with \x59 ('Y')
  Client → Server: topology request (\x00\x00\x00\x0bsecuremote\x00)
  Server → Client: 4-byte header + "CN=<host>,O=<domain>" + 8-byte trailer
"""

import socket
import struct
import threading
import os

HOST = os.environ.get("CHECKPOINT_HOST", "fw1.example.com")
DOMAIN = os.environ.get("CHECKPOINT_DOMAIN", "example.com")
PORT = 264

# https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/checkpoint_hostname.rb#L59
PROBE1 = b"\x51\x00\x00\x00" + b"\x00\x00\x00\x21"
ACK1 = b"\x59\x00\x00\x00" + b"\x00\x00\x00\x00"
PROBE2 = b"\x00\x00\x00\x0bsecuremote\x00"


def build_topology_response(host: str, domain: str) -> bytes:
    payload = f"CN={host},O={domain}".encode()
    header = struct.pack(">I", len(payload))
    trailer = b"\x00" * 8
    return header + payload + trailer


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

        response = build_topology_response(HOST, DOMAIN)
        conn.sendall(response)
        print(f"Served topology to {addr}: CN={HOST},O={DOMAIN}", flush=True)
    except Exception as e:
        print(f"Error handling {addr}: {e}", flush=True)
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", PORT))
        srv.listen(16)
        print(f"Listening on port {PORT} (CN={HOST}, O={DOMAIN})", flush=True)
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
