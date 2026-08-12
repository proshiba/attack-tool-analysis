#!/usr/bin/env python3
"""Authoritative, non-forwarding DNS responder for c2.sliver.lab only."""

from __future__ import annotations

import socket
import struct
import threading


BIND = "192.168.1.50"
PORT = 53
NAME = "c2.sliver.lab"
ANSWER = socket.inet_aton(BIND)


def parse_question(packet: bytes) -> tuple[str, int]:
    offset = 12
    labels: list[str] = []
    while offset < len(packet):
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        if size & 0xC0 or offset + size > len(packet):
            raise ValueError("compressed or truncated query name")
        labels.append(packet[offset : offset + size].decode("ascii"))
        offset += size
    if offset + 4 > len(packet):
        raise ValueError("truncated question")
    return ".".join(labels).lower().rstrip("."), offset + 4


def response(packet: bytes) -> bytes:
    if len(packet) < 12:
        return b""
    try:
        name, question_end = parse_question(packet)
    except (ValueError, UnicodeDecodeError):
        return b""
    qtype, qclass = struct.unpack("!HH", packet[question_end - 4 : question_end])
    is_answer = name == NAME and qtype == 1 and qclass == 1
    flags = 0x8500 if is_answer else 0x8503  # authoritative NOERROR or NXDOMAIN
    header = packet[:2] + struct.pack("!HHHHH", flags, 1, int(is_answer), 0, 0)
    question = packet[12:question_end]
    if not is_answer:
        return header + question
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, len(ANSWER)) + ANSWER
    return header + question + rr


def serve_udp() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((BIND, PORT))
        while True:
            packet, peer = sock.recvfrom(4096)
            reply = response(packet)
            if reply:
                sock.sendto(reply, peer)


def serve_tcp() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((BIND, PORT))
        sock.listen(8)
        while True:
            conn, _ = sock.accept()
            with conn:
                size_bytes = conn.recv(2)
                if len(size_bytes) != 2:
                    continue
                size = struct.unpack("!H", size_bytes)[0]
                packet = b""
                while len(packet) < size:
                    chunk = conn.recv(size - len(packet))
                    if not chunk:
                        break
                    packet += chunk
                reply = response(packet)
                if reply:
                    conn.sendall(struct.pack("!H", len(reply)) + reply)


if __name__ == "__main__":
    threading.Thread(target=serve_tcp, daemon=True).start()
    serve_udp()
