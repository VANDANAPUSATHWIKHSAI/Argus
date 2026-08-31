"""
LLM Loader Module
=================
Loads Qwen3 models for the agent reasoning layers.
Supports:
  1. Local Hugging Face loading (with optional 4-bit/8-bit bitsandbytes quantization).
  2. Ollama API endpoint (convenient for laptop/dev run, e.g. Qwen2.5 / Qwen3).
"""

import os
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

    def _get_ollama_client(self, model_name: str) -> "OllamaWrapper":
        """Returns a helper wrapper to call local Ollama endpoint."""
        return OllamaWrapper(model_name, self.ollama_url)

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
    def __init__(self, model_name: str, base_url: str):
        self.model_name = model_name
        self.base_url = base_url

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        import requests
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model_name.split("/")[-1],  # extract name from path
            "prompt": prompt,
            "stream": False
        }
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            r = requests.post(url, json=payload, timeout=60)
            if r.status_code == 200:
                return r.json().get("response", "")
            else:
                raise RuntimeError(f"Ollama returned error status: {r.status_code}")
        except Exception as e:
            # dev mock fallback if Ollama isn't started yet
            print(f"[OLLAMA WARNING] Connection failed: {e}. Returning mock reasoning response.")
            return (
                f"{{'claim': 'Suspicious PowerShell commands executed by Administrator', "
                f"'evidence_ids': ['F-1001']}}"
            )
