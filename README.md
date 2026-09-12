# Encrypted Banking System with Cryptographic Verification & Proof-of-Work 🏦🔐

A secure, console-based banking application built in C that integrates cryptographic hashing and Proof-of-Work (PoW) consensus algorithms into personal financial transactions. Developed for the **Software Development Fundamentals - 1 (SDF1)** course at **Jaypee Institute of Information Technology**.

---

## 📌 Project Overview

Traditional console-based banking demonstrations store sensitive user credentials and ledger balances in raw plaintext, leaving them vulnerable to direct data manipulation and credential leakage. 

The **Encrypted Banking System** resolves this by employing **OpenSSL SHA-256 cryptographic hashing** to irreversibly hash passwords, generate 6-digit public keys with hash-anchored verification, and require computational **Proof-of-Work (PoW) nonce mining** before executing inter-account transfers. All transactions and user states persist across sessions through structured CSV database files.

---

## ✨ Key Features

* **SHA-256 Authentication:** Passwords are never saved in cleartext; only 64-character hexadecimal SHA-256 hashes are persisted.
* **Public Key Identity:** Every user receives an assigned 6-digit public key and an associated public key hash upon registration, allowing safe peer discovery and transfers.
* **Proof-of-Work (PoW) Mining:** Peer-to-peer transfers execute a mining loop that searches for a valid nonce satisfying leading-zero difficulty constraints before clearing funds.
* **Asynchronous Invoicing / Drafts:** Users can request funds from peers using their public keys. Recipients can later review, accept, or decline pending requests from their draft inbox.
* **Standard Account Operations:** Full support for atomic deposits, withdrawals with insufficient fund checks, and complete transaction history viewing.
* **Persistent File Storage:** Reads and maintains state across multiple flat-file databases (`SDF_PBL-databbase.csv`, `transactions.csv`, and `requests.csv`).

---

## 🛠️ Tech Stack & Requirements

* **Language:** C (Standard C99 or higher)
* **Compiler:** GCC or Clang
* **Libraries:**
  * Standard C Libraries (`stdio.h`, `stdlib.h`, `string.h`, `time.h`)
  * OpenSSL Cryptography Engine (`openssl/sha.h`)

---

## 📂 Database Architecture

The application automatically manages three CSV database files:

| Database File | Purpose | Key Columns / Schema |
| :--- | :--- | :--- |
| `SDF_PBL-databbase.csv` | User Account Registry | `username`, `password_hash`, `public_key`, `public_key_hash`, `balance`, `loan`, `credit`, `debit` |
| `transactions.csv` | Mined Transaction Ledger[cite: 1] | `sender`, `receiver`, `amount`, `nonce`, `signature_hash`, `receiver_public_key`, `timestamp`, `type`[cite: 1] |
| `requests.csv`[cite: 1] | Pending Peer Requests / Drafts[cite: 1] | `requester`, `receiver`, `amount`, `requester_public_key`, `timestamp`[cite: 1] |

---

## ⚙️ Compilation & Setup

### 1. Install OpenSSL Development Libraries

* **Ubuntu / Debian:**
  ```bash
  sudo apt-get update
  sudo apt-get install libssl-dev
