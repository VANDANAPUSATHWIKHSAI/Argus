import sys
import os
import hashlib
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

print("--- Step 1: Verification of imports ---")
try:
    import re2
    print("re2 import: OK")
except ImportError as e:
    print("re2 import: FAILED", e)

try:
    import torch
    print("torch import: OK, version:", torch.__version__)
    print("CUDA available:", torch.cuda.is_available())
    if torch.cuda.is_available():
        print("CUDA device name:", torch.cuda.get_device_name(0))
except ImportError as e:
    print("torch import: FAILED", e)

try:
    import transformers
    from transformers import AutoTokenizer
    print("transformers import: OK, version:", transformers.__version__)
except ImportError as e:
    print("transformers import: FAILED", e)

try:
    import gliner
    from gliner import GLiNER
    print("gliner import: OK, version:", gliner.__version__)
except ImportError as e:
    print("gliner import: FAILED", e)

print("\n--- Step 2: Try loading the model with local_files_only=True ---")
GLINER_MODEL_ID = "gliner-community/gliner_medium-v2.5"
GLINER_REVISION = "88c3b98b57ad5e7d66fb209ed61c53f4b1fd05da"

model = None
tokenizer = None
try:
    model = GLiNER.from_pretrained(
        GLINER_MODEL_ID,
        revision=GLINER_REVISION,
        local_files_only=True
    )
    print("Model loaded successfully from local cache!")
except Exception as e:
    print("Failed to load model from local cache:", e)

try:
    tokenizer = AutoTokenizer.from_pretrained(
        GLINER_MODEL_ID,
        revision=GLINER_REVISION,
        local_files_only=True
    )
    print("Tokenizer loaded successfully from local cache!")
except Exception as e:
    print("Failed to load tokenizer from local cache:", e)

# If local load failed, let's try downloading/caching it (since this script is checking availability/provisioning)
if model is None or tokenizer is None:
    print("\n--- Step 2b: Local files not found, provisioning model/tokenizer (downloading)... ---")
    try:
        model = GLiNER.from_pretrained(
            GLINER_MODEL_ID,
            revision=GLINER_REVISION,
            local_files_only=False
        )
        print("Model downloaded/loaded successfully!")
    except Exception as e:
        print("Failed to download model:", e)

    try:
        tokenizer = AutoTokenizer.from_pretrained(
            GLINER_MODEL_ID,
            revision=GLINER_REVISION,
            local_files_only=False
        )
        print("Tokenizer downloaded/loaded successfully!")
    except Exception as e:
        print("Failed to download tokenizer:", e)

# Locate cache files
print("\n--- Step 3: Local Model Files & Integrity ---")
cache_dir = Path(os.path.expanduser("~/.cache/huggingface/hub"))
model_cache_path = cache_dir / f"models--{GLINER_MODEL_ID.replace('/', '--')}"
print("Expected Cache Directory:", model_cache_path)

if model_cache_path.exists():
    print("Model cache directory exists. File listing:")
    for p in model_cache_path.rglob("*"):
        if p.is_file() and not p.is_symlink():
            # calculate sha256
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            print(f"  - {p.relative_to(model_cache_path)} | Size: {p.stat().st_size} bytes | SHA256: {h.hexdigest()}")
else:
    print("Model cache directory does not exist or is custom.")

print("\n--- Step 4: Inference Testing ---")
sample_text = "The malware Wannacry (attributed to Lazarus Group) spawned tasksche.exe to establish persistence."
labels = ["malware", "threat-actor", "command-line", "process-relationship"]

if model is not None:
    # CPU Inference
    print("Running CPU Inference...")
    import time
    model = model.to("cpu")
    t0 = time.time()
    entities = model.predict_entities(sample_text, labels, threshold=0.3)
    duration_cpu = time.time() - t0
    print(f"CPU Inference completed in {duration_cpu:.4f} seconds. Entities found:")
    for ent in entities:
        print(f"  - {ent['text']} ({ent['label']}) | confidence: {ent['score']:.4f}")

    # GPU Inference if available
    if torch.cuda.is_available():
        print("\nRunning GPU Inference...")
        model = model.to("cuda")
        t0 = time.time()
        # Warmup
        model.predict_entities(sample_text, labels, threshold=0.3)
        t0 = time.time()
        entities = model.predict_entities(sample_text, labels, threshold=0.3)
        duration_gpu = time.time() - t0
        print(f"GPU Inference completed in {duration_gpu:.4f} seconds. Entities found:")
        for ent in entities:
            print(f"  - {ent['text']} ({ent['label']}) | confidence: {ent['score']:.4f}")
    else:
        print("\nGPU Inference not available (CUDA is False)")
else:
    print("Model not available for inference testing.")
