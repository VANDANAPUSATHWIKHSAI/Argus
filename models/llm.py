"""
LLM Loader Module
=================
Loads Qwen3 models for the agent reasoning layers.
Supports:
  1. OpenAI-compatible remote endpoints (OmniRoute, vLLM, LiteLLM, OpenRouter, etc.).
  2. Ollama API endpoint (convenient for local dev run).
  3. Local Hugging Face loading (with optional 4-bit/8-bit quantization).
"""

import os
import json
import logging
from typing import Any, Optional
from config.settings import settings

logger = logging.getLogger(__name__)


class OpenAICompatibleWrapper:
    """
    Wrapper for OpenAI-compatible chat/completions endpoints.
    Compatible with OmniRoute, vLLM, LiteLLM, Ollama (/v1), OpenRouter, etc.
    Fails closed with descriptive, credential-redacted diagnostics when unavailable.
    """
    def __init__(
        self,
        model_name: str,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: int = 120,
        allow_mock: bool = False
    ):
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.allow_mock = allow_mock

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        import requests
        import time

        url = f"{self.base_url}/chat/completions"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 4096,
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        connect_timeout = float(os.getenv("LLM_CONNECT_TIMEOUT", "3.0"))
        read_timeout = float(os.getenv("LLM_READ_TIMEOUT", str(self.timeout)))
        timeout_tuple = (connect_timeout, read_timeout)
        max_retries = int(os.getenv("LLM_MAX_RETRIES", "1"))
        last_error = None
        for attempt in range(max_retries + 1):
            try:
                r = requests.post(url, json=payload, headers=headers, timeout=timeout_tuple)
                if r.status_code == 200:
                    data = r.json()
                    choices = data.get("choices", [])
                    if choices and "message" in choices[0]:
                        return choices[0]["message"].get("content", "")
                    elif choices and "text" in choices[0]:
                        return choices[0].get("text", "")
                    return ""
                elif r.status_code in (429, 502, 503, 504) and attempt < max_retries:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                else:
                    raise RuntimeError(f"Remote LLM returned error HTTP {r.status_code}: {r.text[:200]}")
            except Exception as e:
                last_error = e
                is_conn_refused = "10061" in str(e) or "ConnectionRefused" in str(e) or "actively refused" in str(e)
                if attempt < max_retries and not isinstance(e, RuntimeError) and not is_conn_refused:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                break

        if self.allow_mock:
            # Fallback for mocked test environments only
            logger.warning("Remote LLM connection failed: %s. Returning mock reasoning response.", last_error)
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
                "claims": [{
                    "claim_id": "CLM-AG-EML-001",
                    "summary": "Phishing Email and Executable Attachment Correlation",
                    "findings_summary": "Suspicious phishing email received with executable attachment security_update.bat.",
                    "cited_evidence_ids": finding_ids[:5],
                    "correlation_type": "shared_artifact",
                    "assessed_importance": "critical",
                    "confidence_score": 0.95,
                    "reasoning_notes": "Correlated email header headers and payload observables with executable file activity."
                }],
                "infection_path": {
                    "entry_point": "Bulk simulated infection",
                    "evidence_ids": finding_ids[:1],
                    "confidence": 0.99
                },
                "attack_timeline": claims,
                "attack_chain": [{
                    "stage": "Execution",
                    "events": ["Simulated event execution"],
                    "evidence_ids": finding_ids[:2],
                    "confidence": 0.9
                }],
                "lateral_movement": [],
                "missing_expected_events": [],
                "reconstruction_summary": "Successfully reconstructed timeline for mock.",
                "overall_confidence": 0.95
            })

        sanitized_host = self.base_url.split("@")[-1]
        raise RuntimeError(f"Remote LLM inference failed on '{sanitized_host}' for model '{self.model_name}': {last_error}") from last_error


class LLMLoader:
    """
    LLM Loader class.
    Provides standard interfaces to invoke the LLM from agents.
    Automatically routes to OpenAI-compatible endpoints (OmniRoute/vLLM),
    local Ollama daemon, or local Hugging Face.
    """

    def __init__(self):
        explicit_provider = os.getenv("LLM_PROVIDER", "").lower()
        ollama_env = os.getenv("USE_OLLAMA")
        base_url_env = os.getenv("LLM_BASE_URL") or os.getenv("OPENAI_BASE_URL")

        opencode_url = self._read_opencode_base_url()

        if explicit_provider in ("openai", "openai_compatible", "remote", "omniroute"):
            self.provider = "openai_compatible"
        elif explicit_provider == "ollama":
            self.provider = "ollama"
        elif explicit_provider in ("huggingface", "local"):
            self.provider = "huggingface"
        elif base_url_env or opencode_url:
            self.provider = "openai_compatible"
        elif ollama_env is not None and ollama_env.lower() == "false":
            self.provider = "huggingface"
        else:
            self.provider = "ollama"

        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.ollama_timeout = int(os.getenv("OLLAMA_TIMEOUT", "600"))

        # Remote OpenAI-compatible config
        self.remote_base_url = base_url_env or self._read_opencode_base_url() or "http://127.0.0.1:20128/v1"
        self.remote_api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or self._read_opencode_api_key()
        self.remote_timeout = int(os.getenv("LLM_TIMEOUT", os.getenv("OPENAI_TIMEOUT", "120")))
        self.remote_model_name = os.getenv("LLM_MODEL_NAME") or getattr(settings, "llm_model_name", "Qwen/Qwen3-8B")

    @property
    def use_ollama(self) -> bool:
        return self.provider == "ollama"

    def _read_opencode_base_url(self) -> Optional[str]:
        try:
            if os.path.exists("opencode.json"):
                with open("opencode.json", "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                return cfg.get("provider", {}).get("omniroute", {}).get("options", {}).get("baseURL")
        except Exception:
            pass
        return None

    def _read_opencode_api_key(self) -> Optional[str]:
        try:
            if os.path.exists("opencode.json"):
                with open("opencode.json", "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                key_ref = cfg.get("provider", {}).get("omniroute", {}).get("options", {}).get("apiKey", "")
                if key_ref and key_ref.startswith("{file:") and key_ref.endswith("}"):
                    key_file = os.path.expanduser(key_ref[6:-1])
                    if os.path.exists(key_file):
                        with open(key_file, "r", encoding="utf-8") as kf:
                            return kf.read().strip()
        except Exception:
            pass
        return None

    def _get_client(self, model_name: str) -> Any:
        if self.provider == "openai_compatible":
            return OpenAICompatibleWrapper(
                model_name=self.remote_model_name or model_name,
                base_url=self.remote_base_url,
                api_key=self.remote_api_key,
                timeout=self.remote_timeout
            )
        elif self.provider == "ollama":
            return self._get_ollama_client(model_name)
        else:
            return self._load_hf_model(model_name, quantize=True)

    def load_primary(self) -> Any:
        """Loads the primary agent model (Qwen3-8B)."""
        return self._get_client(settings.llm_model_name)

    def load_fallback(self) -> Any:
        """Loads the fallback model (Qwen3-8B 4-bit)."""
        return self._get_client(settings.llm_fallback_model)

    def load_qwen3_8b(self) -> Any:
        """Loads Qwen3-8B required for primary agent reasoning (e.g. Agent 1)."""
        model_name = getattr(settings, "llm_fallback_model", "Qwen/Qwen3-8B")
        return self._get_client(model_name)

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
