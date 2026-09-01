"""
Classifier Loaders Module
=========================
Loads pre-trained models for:
  - DeBERTa-v3-large-MNLI        → Agent 7 Call 2 (entailment verification)
  - DeBERTa-v3-prompt-injection  → Sanitization Gateway
  - GLiNER                       → Artifact Extraction (zero-shot NER)
  - Pre-trained BERT/RoBERTa     → Email phishing classification
"""

import logging
from typing import Any, List, Dict
from transformers import pipeline

logger = logging.getLogger(__name__)


_CLASSIFIER_CACHE: Dict[str, Any] = {}

class ClassifierLoader:
    """
    Lazy loading wrapper for pre-trained classifiers.
    Avoids downloading models until they are explicitly needed.
    """
    _startup_checked = False
    _semantic_layer_active = False

    def __init__(self):
        self._mnli = _CLASSIFIER_CACHE.get("mnli")
        self._injection_detector = _CLASSIFIER_CACHE.get("injection_detector")
        self._gliner = _CLASSIFIER_CACHE.get("gliner")
        self._phishing_classifier = _CLASSIFIER_CACHE.get("phishing_classifier")

    def verify_semantic_layer(self) -> bool:
        """
        One-time check to verify if the semantic layer (prompt injection detector)
        loads successfully. Logs whether the semantic layer is active.
        """
        if not ClassifierLoader._startup_checked:
            try:
                # Attempt to load the model
                self.load_injection_detector()
                ClassifierLoader._semantic_layer_active = True
                logger.info("Semantic layer (prompt injection detector) is active.")
            except Exception as e:
                ClassifierLoader._semantic_layer_active = False
                logger.error(f"Semantic layer (prompt injection detector) startup check failed: {e}", exc_info=True)
            finally:
                ClassifierLoader._startup_checked = True
        return ClassifierLoader._semantic_layer_active

    def load_mnli(self) -> Any:
        """
        Loads DeBERTa-v3-large-MNLI for zero-shot entailment.
        Used by Agent 7 Call 2 to check if evidence supports the claim.
        """
        if not self._mnli:
            model_id = "MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli"
            print(f"[Classifier] Loading zero-shot entailment model: {model_id}...")
            self._mnli = pipeline("zero-shot-classification", model=model_id)
            _CLASSIFIER_CACHE["mnli"] = self._mnli
        return self._mnli

    def load_injection_detector(self) -> Any:
        """
        Loads DeBERTa-v3-base-prompt-injection-v2.
        Used by Sanitization Gateway to detect malicious instructions.
        """
        if not self._injection_detector:
            if "injection_detector" in _CLASSIFIER_CACHE:
                self._injection_detector = _CLASSIFIER_CACHE["injection_detector"]
            else:
                model_id = "protectai/deberta-v3-base-prompt-injection-v2"
                print(f"[Classifier] Loading prompt injection classifier: {model_id}...")
                self._injection_detector = pipeline("text-classification", model=model_id)
                _CLASSIFIER_CACHE["injection_detector"] = self._injection_detector
        return self._injection_detector

    def load_gliner(self) -> Any:
        """
        Loads GLiNER zero-shot NER model.
        Used by Artifact Extractor to pull IOCs/keys dynamically.
        """
        if not self._gliner:
            from gliner import GLiNER
            model_id = "urchade/gliner_medium-v2.1"
            print(f"[Classifier] Loading GLiNER model: {model_id}...")
            self._gliner = GLiNER.from_pretrained(model_id)
        return self._gliner

    def load_phishing_classifier(self) -> Any:
        """
        Loads pre-trained phishing detection classifier.
        Used by Email Forensic Engine (Layer 4).
        """
        if not self._phishing_classifier:
            model_id = "ealvaradob/bert-finetuned-phishing"
            print(f"[Classifier] Loading phishing detection model: {model_id}...")
            self._phishing_classifier = pipeline("text-classification", model=model_id)
        return self._phishing_classifier

    def predict_phishing(self, text: str) -> Dict[str, Any]:
        """
        Predicts whether the given text is phishing or benign.
        Returns a dict with 'label' and 'confidence'.
        """
        classifier = self.load_phishing_classifier()
        res = classifier(text)[0]
        return {
            "label": res["label"],
            "confidence": float(res["score"])
        }

