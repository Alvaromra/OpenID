# ctxcap — Context Capsules

A portable, verifiable format for transmitting context between AI chat sessions, reducing hallucination through cryptographic integrity and grounding protocols.

## The problem

Language models **hallucinate** when they don't know something and **forget** context when you open a new chat. Pasting raw text works but gives you no way to prove the content is the original, nor to instruct the model to admit when something falls outside what was provided.

## The solution

ctxcap packages your facts and documents into a **capsule** where each piece has a CID — an identifier that is literally the SHA-256 hash of its own content (CIDv1, IPFS-compatible). It generates a **grounding prompt** that instructs the model to respond only from the provided facts, cite its sources, and say "out of verified context" instead of making things up.

```bash
python3 ctxcap.py ingest document.pdf -o capsule.json
python3 ctxcap.py pack capsule.json "what dataset and sample size?" -k 3 --terse
# paste the output into the chat → grounded, citable, verifiable answers
```

## Features

**Integrity via content addressing** — every statement gets a CID (hash = identity). Change one character, the CID changes. The root CID identifies the entire capsule. Verifiable with `ctxcap.py verify`.

**Direct file reading** — `ingest` reads text, code, and PDF (with OCR via Tesseract for scanned pages). No need to write JSON by hand.

**Relevance selection** — `pack` ranks facts by TF-IDF against your query and sends only the relevant ones. 60–85% input token savings.

**Compact prompt** — short IDs (`#xxxx`) instead of full CIDs, rules in one line. Combined with `pack`, delivers maximum token savings.

**Terse output** — `--terse` appends an instruction requesting direct answers with no preamble or closing. Cuts response tokens.

**Message shrinker** — `shrink` compresses your instruction by removing pleasantries and redundancy. Offline, rule-based.

**Browser interface** — `ctxcap-tool.html` does everything without installing anything: drag files, generate capsules, verify hashes, shrink messages. Live token estimation included.

**Interoperability** — real CIDv1 and CARv1 (same as IPFS). Canonical JSON content. Python and HTML produce identical CIDs.

## Installation

Python 3.10+ with stdlib only. No external dependencies for basic use.

```bash
git clone https://github.com/Alvaromra/OpenID.git
cd OpenID
python3 ctxcap.py --help
```

For PDF reading with OCR (optional):

```bash
sudo apt install poppler-utils tesseract-ocr tesseract-ocr-por
pip install pdfplumber pdf2image pytesseract pillow --break-system-packages
```

Browser interface: open `ctxcap-tool.html` in your browser. No installation needed.

## Quick start

### Ingest files into a capsule

```bash
# single file
python3 ctxcap.py ingest document.py -o capsule.json

# entire directory (recursive, skips venv/.git/__pycache__)
python3 ctxcap.py ingest ~/my-project -r -o capsule.json

# PDF with automatic OCR for scanned pages
python3 ctxcap.py ingest report.pdf -o capsule.json
```

### Generate a prompt to paste into the chat

```bash
# full format
python3 ctxcap.py prompt capsule.json

# compact + terse output (maximum token savings)
python3 ctxcap.py prompt capsule.json --compact --terse

# only facts relevant to your question
python3 ctxcap.py pack capsule.json "what dataset was used?" -k 3 --terse
```

### Verify integrity

```bash
python3 ctxcap.py verify capsule.json
python3 ctxcap.py verify capsule.car
```

### Shrink your message

```bash
python3 ctxcap.py shrink "Hello, could you please help me with this?" --show
```

### Create a capsule from hand-written facts

```bash
python3 ctxcap.py create examples/exemplo_entrada.json -o capsule.json --car capsule.car
```

## How it works

### Merkle-DAG

Each **statement** (a fact, document excerpt, code snippet) becomes a canonical JSON block. Its SHA-256 hash becomes its **CID** (Content IDentifier). A **manifest** lists all statement CIDs and has its own CID — the capsule's **root CID**. Changing any character in any statement changes its CID, which changes the manifest, which changes the root. Tampering is detectable.

### Grounding protocol

The generated prompt instructs the model to: treat only those statements as truth, cite the IDs it used, say "out of verified context" if the question isn't covered, and never contradict a verified statement. This doesn't prevent hallucination (no hash does), but changes the usage protocol — it creates a clear boundary between verified context and free generation.

### Interoperability

CIDs are real CIDv1: version=1, codec raw (0x55), multihash sha2-256, multibase base32 (prefix `bafkrei...`). The `.car` format follows CARv1 with a CBOR dag-cbor header. Any IPFS/IPLD tool that understands CIDv1 can read the identifiers.

## Honest limits

Hash proves **integrity**, not **authorship** — for authorship, sign the root CID (Ed25519 fits naturally). Hash proves the content wasn't altered, not that it's *true in the world* — source curation is still your job. The model in the chat **cannot reliably compute SHA-256** — hash verification is done by code (`verify`), never by the model. Token estimation is approximate (~15% variance vs the model's actual tokenizer).

## Structure

```
ctxcap.py           CLI (Python 3.10+, stdlib only)
ctxcap-tool.html    Browser interface (self-contained)
examples/           Example inputs
LICENSE             MIT
```

## License

MIT
