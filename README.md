# SecureCommunicationCLI

## Author

- Full Name: Karam Aboul-Hosn

## Introduction
SecureCommunications is a lightweight educational project demonstrating how two clients can establish an end-to-end encrypted communication channel using:

- A relay server that cannot read messages  
- Elliptic-curve Diffie-Hellman for key exchange  
- AES-256-GCM for authenticated encryption  
- HKDF for key derivation  

The server only forwards encrypted payloads between clients. All cryptographic operations happen on the clients, making this a small-scale simulation of modern secure messaging protocols (e.g. Signal-style ECDH key exchange with AEAD).

## Features

### End-to-End Encryption
- Clients use X25519 Diffie-Hellman to establish a shared secret
- A 256-bit symmetric key is derived using HKDF-SHA256
- All communication is encrypted using AES-GCM, providing confidentiality and authentication

### Relay
The relay server never decrypts or inspects messages, it only matches clients into pairs and relays encrypted frames.

## Requirements
- Python 3.8+
- `cryptography` library (`pip install cryptography`)

## How to Run
1. **Install dependencies**:
   ```bash
   pip install cryptography


## Screenshot
Here’s a snapshot of the one-way communication in action between the two clients after running server.py:

![Client1 Communication Screenshot]
![image](Photos/client1.png)

![Client2 Communication Screenshot]
![image](Photos/client2.png)
