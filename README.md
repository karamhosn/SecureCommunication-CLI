# SecureCommunicationCLI

## Introduction
**SecureCommunications** is a lightweight educational project demonstrating how two clients can establish an end-to-end encrypted communication channel using:

- A simple relay server (which cannot read messages)  
- X25519 (Elliptic-curve Diffie-Hellman) for key exchange  
- AES-256-GCM for authenticated encryption  
- HKDF (SHA-256) for key derivation  

The server only forwards encrypted payloads between clients.  
All cryptographic operations happen on the clients, making this a small-scale simulation of modern secure messaging protocols (e.g., Signal-style ECDH key exchange + AEAD).

## Features

### End-to-End Encryption
- Clients use **X25519 Diffie-Hellman** to establish a shared secret.
- A 256-bit symmetric key is derived using **HKDF-SHA256**.
- All communication is encrypted using **AES-GCM**, providing confidentiality and authentication.

### Relay
- The relay server never decrypts or inspects messages.
- It matches clients into pairs and relays encrypted frames.

### User-Friendly Interface
- Clean startup messages.
- Easy exit
- Clear fingerprint comparison instructions.
- Graceful shutdown and reconnection handling.

## Requirements
- Python 3.x
- `cryptography` library (`pip install cryptography`)

## How to Run
1. **Install dependencies**:
   ```bash
   pip install cryptography


## Screenshot
Here’s a snapshot of the one-way communication in action between the two clients after running server.py:

![Client1 Communication Screenshot]
![image]()

![Client2 Communication Screenshot]
![image]()
