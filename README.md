# Argus — Multi-Agent AI Platform for Digital Forensic Investigation

> Turns raw digital evidence into a cited, verified investigation report.

## Architecture Overview
Evidence Upload → Infrastructure Layer → Evidence Preprocessing →
Forensic Analysis Layer → FIR → Sanitization Gateway →
AI Investigation (Agents 1–7) → Confidence Gate → Human Review →
Report Generation → Validated Case Repository (RAG loop)

## Tech Stack
- **Orchestration**: LangGraph
- **LLM (primary)**: Qwen3-14B
- **LLM (fallback)**: Qwen3-8B (4-bit)
- **Embeddings**: Qwen3-Embedding-4B
- **Vector DB**: Qdrant
- **Graph DB**: Neo4j + GDS
- **Verification**: DeBERTa-v3-large-MNLI
- **Threat Intel**: STIX/TAXII, MITRE ATT&CK, CVE/NVD, CISA KEV
- **Malware**: YARA, Volatility 3

## Setup
\\\ash
pip install -r requirements.txt
cp .env.example .env
\\\
"@

Write-PY "requirements.txt" @"
# Core
python-dotenv
pydantic
fastapi
uvicorn

# Orchestration
langgraph

# LLM / Embeddings (via HuggingFace)
transformers
torch
bitsandbytes
accelerate
sentence-transformers

# Graph DB
neo4j

# Vector DB
qdrant-client

# Forensic parsers
python-evtx
volatility3
pyshark
scapy

# NER / Classifiers
gliner
# roberta (via transformers)

# Threat Intelligence
stix2
taxii2-client
requests

# Report Generation
jinja2
reportlab
weasyprint

# Evaluation
ragas
deepeval

# Utilities
pandas
numpy
cryptography
hashlib
