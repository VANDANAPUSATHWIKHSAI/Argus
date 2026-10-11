"""
Pretrained Models Verification Script
=====================================
Test-loads all classifiers and embedding models to ensure they fetch
correctly from Hugging Face and work as expected.

Usage:
    python verify_models.py
"""

import sys
from models.classifiers import ClassifierLoader
from models.embeddings import EmbeddingLoader


def test_embeddings():
    print("\n" + "=" * 55)
    print(" 1. Testing Embeddings (sentence-transformers)...")
    print("=" * 55)
    try:
        loader = EmbeddingLoader()
        texts = ["Suspicious logon event from unauthorized IP address.", "Normal user login."]
        vectors = loader.encode(texts)
        print(f"  OK - Encoded {len(texts)} sentences.")
        print(f"  Vector size: {len(vectors[0])} dimensions.")
        return True
    except Exception as e:
        print(f"  FAIL - {e}")
        return False


def test_mnli(loader):
    print("\n" + "=" * 55)
    print(" 2. Testing DeBERTa-v3-large-MNLI Entailment Classifier...")
    print("=" * 55)
    try:
        classifier = loader.load_mnli()
        res = classifier(
            sequences="Process powershell.exe executed with encoded command line.",
            candidate_labels=["supports", "neutral", "contradicts"],
            hypothesis_template="This evidence: {}"
        )
        print(f"  Entailment labels: {res['labels']}")
        print(f"  Entailment scores: {[round(s, 4) for s in res['scores']]}")
        print("  OK - DeBERTa-v3-large-MNLI active.")
        return True
    except Exception as e:
        print(f"  FAIL - {e}")
        return False


def test_phishing_detector(loader):
    print("\n" + "=" * 55)
    print(" 3. Testing BERT Phishing Email Classifier...")
    print("=" * 55)
    try:
        classifier = loader.load_phishing_classifier()
        
        # Test sample
        email = "Dear customer, your bank account has been locked. Click here to reset: http://malicious.com"
        result = classifier(email)[0]
        print(f"  Sample result: {result}")
        print("  OK - Phishing classifier active.")
        return True
    except Exception as e:
        print(f"  FAIL - {e}")
        return False


def test_gliner(loader):
    print("\n" + "=" * 55)
    print(" 4. Testing GLiNER Zero-Shot Named Entity Recognition...")
    print("=" * 55)
    try:
        model = loader.load_gliner()
        text = "Process powershell.exe connected to command and control IP 185.220.101.5"
        labels = ["IP Address", "Executable", "Technique"]
        
        entities = model.predict_entities(text, labels)
        print("  Entities found:")
        for entity in entities:
            print(f"    - {entity['text']} => {entity['label']} (confidence: {entity['score']:.2f})")
        print("  OK - GLiNER active.")
        return True
    except Exception as e:
        print(f"  FAIL - {e}")
        return False


if __name__ == "__main__":
    print("=" * 55)
    print("  Argus — Pretrained Models Verification")
    print("=" * 55)

    loader = ClassifierLoader()
    
    results = {
        "Embeddings":            test_embeddings(),
        "DeBERTa-v3-large-MNLI": test_mnli(loader),
        "Phishing Classifier":  test_phishing_detector(loader),
        "GLiNER Zero-Shot NER": test_gliner(loader),
    }

    print("\n" + "=" * 55)
    all_ok = all(results.values())
    for model, ok in results.items():
        status = "OK  " if ok else "FAIL"
        print(f"  [{status}] {model}")
    print("=" * 55)

    if all_ok:
        print("\n  All pre-trained classifiers and embeddings are downloaded and verified!")
    else:
        sys.exit(1)
