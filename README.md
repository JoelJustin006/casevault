# 🛡️ CaseVault

![Django](https://img.shields.io/badge/Django-5.2-092E20?style=flat&logo=django)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![Status](https://img.shields.io/badge/Status-Hackathon%20Project-orange)
![Cryptography](https://img.shields.io/badge/Crypto-SHA--256%20%2B%20Ed25519-success)

CaseVault is a Django web app that gives digital evidence a **cryptographic chain of custody**. Every seized file gets SHA-256 fingerprinted at ingest, every access becomes a signed block in an append-only hash chain, and any judge can verify a copy in a public portal — no login required.

---

## What it does

Files are hashed on upload and anchored to an immutable ledger. Every view, download, transfer, and verification is a new block, cryptographically signed with the actor's Ed25519 key. If anyone — even a system administrator — alters a past block, the chain breaks instantly and every subsequent block becomes invalid.

Officers, forensic analysts, judges, and advocates are all scoped to what they're legally entitled to see. Custody transfers require two signatures. Entire cases can be sealed with a single Merkle root.

---

## Features

- **SHA-256 fingerprinting** at ingest — computed from raw bytes before storage
- **Append-only hash chain** — each block hashes the one before it
- **Ed25519 digital signatures** — every block signed by its author
- **Dual-signature custody transfers** — sender initiates, receiver countersigns
- **Role-based access control** — Officer, Forensics, Judge, Advocate, Admin
- **Rank hierarchy** — Constable → Deputy Superintendent, Junior Analyst → Chief Forensic Officer
- **Warrant tethering** — every evidence item can reference a legal warrant, with expiry alerts
- **Merkle tree case sealing** — one hash anchors every file in a case
- **AI custody narratives** — natural-language summaries generated from the chain
- **AI risk scoring** — 0–100 per item with explainable contributing factors
- **Public verification portal** — anyone can upload a file and prove it matches the ledger
- **Court Package export** — ZIP with original bytes, manifest, and printable HTML certificate
- **Evidence linking graph** — visual network of cases, officers, and evidence
- **Live tamper detection** — web-based simulation tool for demos
- **Login audit trail** — every attempt logged with IP and device fingerprint
- **Auto-lockout** — 5 failed attempts trigger a 15-second freeze
- **Security headers** — strict CSP, X-Frame-Options DENY, HSTS, Referrer-Policy

## Screenshots

### 🏠 Home page
![Home page](screenshots/Screenshot-1.png)

### 📊 Dashboard
![Dashboard](screenshots/Screenshot-2.png)

### 📁 Cases
![Cases](screenshots/Screenshot-3.png)

### 🔍 Evidence detail with AI narrative
![Evidence detail](screenshots/Screenshot-4.png)

### 🕸️ Evidence linking graph
![Evidence graph](screenshots/Screenshot-5.png)

### 🚨 Live tamper detection
![Tamper detection](screenshots/Screenshot-6.png)

### ✅ Public verification portal
![Public verify](screenshots/Screenshot-7.png)

### 📋 Case summary
![Case summary](screenshots/Screenshot-8.png)

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR-USERNAME/casevault.git
cd casevault

# Virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux

# Install dependencies
pip install django cryptography "qrcode[pil]"

# Set up the database
python manage.py makemigrations vault
python manage.py migrate

# Seed demo users
python manage.py seed_demo

# Run
python manage.py runserver
