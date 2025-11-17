import socket
import threading
import struct

HOST = "localhost"
PORT = 12345


# Framing helpers

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes, or raise if connection closes early."""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Socket closed while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> bytes:
    """[4-byte length][payload]"""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length == 0:
        return b""
    return recv_exact(sock, length)


def send_frame(sock: socket.socket, data: bytes) -> None:
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)


# Relay logic

def relay(src: socket.socket, dst: socket.socket, label: str):
    """Read frames from src and forward them to dst."""
    try:
        while True:
            frame = recv_frame(src)
            send_frame(dst, frame)
    except Exception as e:
        print(f"[{label}] relay ended: {e}")
    finally:
        src.close()
        dst.close()


def handle_pair(conn1: socket.socket, addr1, conn2: socket.socket, addr2):
    print(f"[+] Paired {addr1} <-> {addr2}")
    t1 = threading.Thread(target=relay, args=(conn1, conn2, f"{addr1}→{addr2}"), daemon=True)
    t2 = threading.Thread(target=relay, args=(conn2, conn1, f"{addr2}→{addr1}"), daemon=True)
    t1.start()
    t2.start()


def run_server():
    waiting_conn = None
    waiting_addr = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[+] Relay server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            print(f"[+] Client connected from {addr}")

            if waiting_conn is None:
                # First client waiting for a partner
                waiting_conn = conn
                waiting_addr = addr
                print("[ ] Waiting for another client to pair...")
            else:
                # Pair with waiting client
                handle_pair(waiting_conn, waiting_addr, conn, addr)
                waiting_conn = None
                waiting_addr = None


if __name__ == "__main__":
    run_server()
