import socket
import struct
import threading
import os

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

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


# Receiving thread

def receive_messages(sock: socket.socket, aesgcm: AESGCM, peer_left_event: threading.Event):
    """Background thread to receive and decrypt messages from the peer."""
    try:
        while True:
            frame = recv_frame(sock)
            if not frame:
                # Peer closed connection cleanly
                print("\nPeer has left the session.")
                peer_left_event.set()
                break

            if len(frame) < 12:
                # Malformed frame, ignore
                continue

            nonce = frame[:12]
            ciphertext = frame[12:]

            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
                msg = plaintext.decode("utf-8", errors="replace")
                print(f"\nPeer: {msg}")
                print("You: ", end="", flush=True)
            except Exception as e:
                print(f"\n[!] Decryption failed: {e}")
                print("You: ", end="", flush=True)

    except ConnectionError:
        # Socket closed while reading — peer left or we closed
        if not peer_left_event.is_set():
            print("\nPeer has left the session.")
            peer_left_event.set()
    except Exception as e:
        print(f"\n[!] Receive thread error: {e}")
        peer_left_event.set()
    finally:
        try:
            sock.close()
        except OSError:
            pass


# One encrypted session with a peer

def run_single_session() -> tuple[bool, bool]:
    """
    Run a single secure session with one peer.
    Returns (peer_left, user_quit):

    - peer_left = True  if the remote peer disconnected first.
    - user_quit = True  if the local user typed 'quit'/'exit'.
    """
    peer_left_event = threading.Event()
    user_quit = False

    print("Connecting to relay server...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print("Successfully connected. Performing ECDH key exchange...")

        # ---- ECDH key exchange (X25519) ----
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        our_pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Send our public key
        send_frame(sock, our_pub_bytes)

        # Receive peer public key
        peer_pub_bytes = recv_frame(sock)
        if len(peer_pub_bytes) != 32:
            raise ValueError("Unexpected peer public key length")

        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)

        # Derive shared secret
        shared_secret = private_key.exchange(peer_public_key)

        # Derive AES-GCM key via HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"demo-ecdh-chat",
        )
        aes_key = hkdf.derive(shared_secret)
        aesgcm = AESGCM(aes_key)

        # Compute key fingerprint
        digest = hashes.Hash(hashes.SHA256())
        digest.update(aes_key)
        key_hash = digest.finalize()
        fingerprint = key_hash.hex()[:32]  # short display version

        # ---- Friendly intro text ----
        print("\nWelcome to SecureCommunications!\n")
        print(f"Key Fingerprint:  {fingerprint}\n")
        print("Compare this with your partner via a trusted channel.")
        print("If they match, you may begin secure communication.\n")
        print("Enter \"quit\" or \"exit\" to leave this chat room.\n")

        # Start background receiver
        recv_thread = threading.Thread(
            target=receive_messages,
            args=(sock, aesgcm, peer_left_event),
            daemon=True,
        )
        recv_thread.start()

        # Main loop: send messages
        try:
            while True:
                # If peer already left, break so outer logic can handle wait/quit prompt
                if peer_left_event.is_set():
                    break

                msg = input("You: ")
                if msg.lower() in ("quit", "exit"):
                    user_quit = True
                    break

                # If peer left while we were typing
                if peer_left_event.is_set():
                    break

                plaintext = msg.encode("utf-8")
                nonce = os.urandom(12)  # 96-bit nonce for GCM
                ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
                try:
                    send_frame(sock, nonce + ciphertext)
                except OSError:
                    # Socket likely closed due to peer leaving
                    if not peer_left_event.is_set():
                        print("\nPeer has left the session.")
                        peer_left_event.set()
                    break

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            user_quit = True

    # At this point, socket is closed; check if peer left
    peer_left = peer_left_event.is_set()
    return peer_left, user_quit


# Outer loop: allow waiting & reconnecting

def run_client():
    while True:
        peer_left, user_quit = run_single_session()

        if user_quit:
            print("\nThank you for using SecureCommunications!")
            break

        if peer_left:
            # Peer disconnected first
            choice = input(
                '\nPeer has left the session.\n'
                'Type "wait" to wait for a new partner (or for them to rejoin),\n'
                'or type "quit" to exit: '
            ).strip().lower()

            if choice in ("quit", "exit", "q", "no", "n", ""):
                print("\nThank you for using SecureCommunications!")
                break
            else:
                # Loop again → start a new session, connect to server, wait to be paired
                continue

        # Fallback: if neither peer_left nor user_quit, just exit
        print("\nThank you for using SecureCommunications!")
        break


if __name__ == "__main__":
    run_client()
