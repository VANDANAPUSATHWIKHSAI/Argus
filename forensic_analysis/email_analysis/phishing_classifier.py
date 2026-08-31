# Fine-tuned RoBERTa phishing classifier


class PhishingClassifier:
    """Classifies email text as phishing or legitimate using a fine-tuned RoBERTa model."""

    def predict(self, email_text: str) -> dict:
        """Return a prediction dict with keys 'label' and 'score'."""
        raise NotImplementedError
