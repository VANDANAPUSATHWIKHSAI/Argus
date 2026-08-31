import re

class PIIRedactor:
    """
    PIIRedactor handles write-time PII & secrets redaction.
    Scrubs credit cards, Aadhaar numbers, emails, phone numbers, addresses,
    credentials, and system artifacts, replacing them with placeholders.
    """

    REDACTOR_VERSION = "1.0.0"

    PII_PATTERNS = {
        # CREDIT_CARD: 16 digits (xxxx-xxxx-xxxx-xxxx or standard spaced)
        # Checked first to avoid overlap with 12-digit Aadhaar
        "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        
        # AADHAAR: 12 digits (xxxx xxxx xxxx or xxxx-xxxx-xxxx or xxxxxxxxxxxx)
        "AADHAAR": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        
        # Email Addresses
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        
        # Phone Numbers: US (xxx-xxx-xxxx) and Indian (xxxxx-xxxxx) layouts, excluding IP addresses
        "PHONE": r"(?<![\d\.])(?:\+?\d{1,3}[-\s]?)?(?:\(?\d{3}\)?[\-\s]\d{3}[\-\s]\d{4}|\d{5}[\-\s]\d{5})(?![\d\.])",

        # Addresses (standard keyword-based street/ave/road address and Zip/Pin Code indicators)
        "ADDRESS": r"\b\d{1,5}\s+[A-Za-z0-9\.\s]{3,30}\s+(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Court|Ct|Boulevard|Blvd|Way)\b|\bPin\s*Code:\s*\d{6}\b|\bZip:\s*\d{5}\b",

        # Names (Name: First Last format checks)
        "NAME": r"\bName:\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b",

        # Credentials & Secrets (API keys, AWS secrets, passwords)
        "CREDENTIALS": r"(?i)(?:api_key|apikey|private_key|aws_secret|client_secret|db_password|session_token|password|passwd|auth_token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.\/\+\=]{8,}['\"]?",

        # Bearer Tokens & Private Key blocks
        "BEARER_TOKEN": r"\bBearer\s+[A-Za-z0-9_\-\.\=\+]{16,}\b",
        "PRIVATE_KEY": r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",

        # Internal System Artifacts (Prompts, reasoning paths, tool schemas)
        "SYSTEM_ARTIFACTS": r"(?i)(?:system_prompt|agent_instruction|thought:|reasoning:|tool_schema)"
    }

    def __init__(self):
        # Compile PII regexes in exact order
        self.compiled_pii = [
            (label, re.compile(pattern))
            for label, pattern in self.PII_PATTERNS.items()
        ]

    def redact(self, text: str) -> tuple[str, str]:
        """
        Scrubs PII and credentials from the text, replacing them with placeholder tokens.
        Returns: (redacted_text, redactor_version)
        """
        if not text:
            return "", self.REDACTOR_VERSION

        redacted = text
        for label, pattern in self.compiled_pii:
            redacted = pattern.sub(f"[REDACTED_{label}]", redacted)
        return redacted, self.REDACTOR_VERSION

    def redact_with_details(self, text: str) -> tuple[str, str, dict[str, int]]:
        """
        Scrubs PII and credentials from the text, returning redacted text, version,
        and count of redactions per category.
        """
        if not text:
            return "", self.REDACTOR_VERSION, {}

        redacted = text
        counts: dict[str, int] = {}

        for label, pattern in self.compiled_pii:
            matches = pattern.findall(redacted)
            if matches:
                counts[label] = len(matches)
                redacted = pattern.sub(f"[REDACTED_{label}]", redacted)

        return redacted, self.REDACTOR_VERSION, counts
