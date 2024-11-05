# Simple Blockchain with Digital Signatures

This project demonstrates a simple blockchain structure with RSA-based digital signatures. Each block contains transactions signed by users and validated through a Merkle tree structure.

## Features

- **User and Transaction Management:** Users can sign transactions using their private RSA keys.
- **Merkle Tree Verification:** Uses a Merkle tree to securely verify transactions within each block.
- **Proof of Work:** Blocks require a proof-of-work process to be added to the blockchain.
- **Blockchain Integrity Validation:** Validates the blockchain's integrity based on hash checks.

## Getting Started

To run the project, ensure you have Python and the required libraries installed:

```bash
pip install rsa
