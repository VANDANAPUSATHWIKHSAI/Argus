"""
LLM Loader Module
=================
Loads Qwen3 models for the agent reasoning layers.
Supports:
  1. Local Hugging Face loading (with optional 4-bit/8-bit bitsandbytes quantization).
  2. Ollama API endpoint (convenient for laptop/dev run, e.g. Qwen2.5 / Qwen3).
"""

import os
import json
from typing import Any
from config.settings import settings


class LLMLoader:
    """
    LLM Loader class.
    Provides standard interfaces to invoke the LLM from agents.
    """

    def __init__(self):
        self.use_ollama = os.getenv("USE_OLLAMA", "true").lower() == "true"
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.ollama_timeout = int(os.getenv("OLLAMA_TIMEOUT", "600"))

    def load_primary(self) -> Any:
        """
        Loads the primary agent model (Qwen3-14B).
        In dev: returns either an Ollama client wrapper or a Hugging Face pipeline.
        """
        if self.use_ollama:
            return self._get_ollama_client(settings.llm_model_name)
        return self._load_hf_model(settings.llm_model_name, quantize=True)

    def load_fallback(self) -> Any:
        """
        Loads the fallback model (Qwen3-8B 4-bit).
        """
        if self.use_ollama:
            return self._get_ollama_client(settings.llm_fallback_model)
        return self._load_hf_model(settings.llm_fallback_model, quantize=True)

    def load_qwen3_8b(self) -> Any:
        """
        Loads Qwen3-8B required for primary agent reasoning (e.g. Agent 1).
        """
        model_name = getattr(settings, "llm_fallback_model", "Qwen/Qwen3-8B")
        if self.use_ollama:
            return self._get_ollama_client(model_name)
        return self._load_hf_model(model_name, quantize=True)

    def _get_ollama_client(self, model_name: str) -> "OllamaWrapper":
        """Returns a helper wrapper to call local Ollama endpoint."""
        return OllamaWrapper(model_name, self.ollama_url, timeout=self.ollama_timeout)

    def _load_hf_model(self, model_id: str, quantize: bool = True) -> Any:
        """
        Loads model from Hugging Face.
        Quantization: bitsandbytes nf4, double quant, bf16 compute dtype.
        """
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

        print(f"[LLM] Loading {model_id} via Hugging Face...")
        tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)

        kwargs = {"trust_remote_code": True, "device_map": "auto"}
        if quantize and torch.cuda.is_available():
            from transformers import BitsAndBytesConfig
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=torch.bfloat16
            )
            kwargs["quantization_config"] = bnb_config
        elif not torch.cuda.is_available():
            print("[LLM WARNING] CUDA not available, loading model on CPU (unquantized/slow).")

        model = AutoModelForCausalLM.from_pretrained(model_id, **kwargs)
        
        # Return a simple text generation pipeline
        return pipeline(
            "text-generation",
            model=model,
            tokenizer=tokenizer,
            max_new_tokens=512,
            temperature=0.7,
            top_p=0.9
        )


class OllamaWrapper:
    """Simple wrapper to query Ollama chat/generation endpoint."""
    def __init__(self, model_name: str, base_url: str, allow_mock: bool = False, timeout: int = 600):
        self.model_name = model_name
        self.base_url = base_url
        self.allow_mock = allow_mock
        self.timeout = timeout

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        import requests
        import json

        url = f"{self.base_url}/api/generate"

        model_name = self.model_name
        if model_name in ("Qwen/Qwen3-8B", "Qwen3-8B"):
            model_name = "qwen3:8b"
        elif "/" in model_name:
            model_name = model_name.split("/")[-1]

        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False
        }
        if system_prompt:
            payload["system"] = system_prompt
        timeout = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", str(self.timeout)))
        try:
            r = requests.post(url, json=payload, timeout=timeout)
            if r.status_code == 200:
                return r.json().get("response", "")
            else:
                raise RuntimeError(f"Ollama returned error status: {r.status_code}")
        except Exception as e:
            if self.allow_mock:
                print(f"[OLLAMA WARNING] Connection failed: {e}. Returning smart mock reasoning response.")
                import re
                finding_ids = re.findall(r'<finding id=[\'"]([^\'"]+)[\'"]>', prompt)
                if not finding_ids:
                    finding_ids = re.findall(r'Finding \[([a-f0-9\-]+)\]', prompt) or ["F-1001", "F-1002"]
                    
                claims = []
                chunk_size = 50
                for i in range(0, len(finding_ids), chunk_size):
                    chunk = finding_ids[i:i+chunk_size]
                    claims.append({
                        "timestamp": "2026-09-23T10:00:00Z",
                        "event": f"Bulk correlation of {len(chunk)} events",
                        "stage": "Execution",
                        "mitre_technique": "T1059",
                        "evidence_ids": chunk,
                        "confidence": 0.95
                    })
                
                return json.dumps({
                    "claims": [
                        {
                            "claim_id": "CLM-AG-EML-001",
                            "summary": "Phishing Email and Executable Attachment Correlation",
                            "findings_summary": "Suspicious phishing email received with executable attachment security_update.bat.",
                            "cited_evidence_ids": finding_ids[:5],
                            "correlation_type": "shared_artifact",
                            "assessed_importance": "critical",
                            "confidence_score": 0.95,
                            "reasoning_notes": "Correlated email header headers and payload observables with executable file activity."
                        }
                    ],
                    "infection_path": {
                        "entry_point": "Bulk simulated infection",
                        "evidence_ids": finding_ids[:1],
                        "confidence": 0.99
                    },
                    "attack_timeline": claims,
                    "attack_chain": [
                        {
                            "stage": "Execution",
                            "events": ["Simulated event execution"],
                            "evidence_ids": finding_ids[:2],
                            "confidence": 0.9
                        }
                    ],
                    "lateral_movement": [],
                    "missing_expected_events": [],
                    "reconstruction_summary": "Successfully reconstructed timeline for mock.",
                    "overall_confidence": 0.95
                })
            raise RuntimeError(f"Ollama generation failed for model '{model_name}': {e}") from e
