import pytest
try:
    from models.classifiers import ClassifierLoader
except ModuleNotFoundError:
    from argus.models.classifiers import ClassifierLoader

def test_phishing_classifier_predictions():
    loader = ClassifierLoader()
    
    phishing_sample = "Urgent: Your account is locked. Verify at http://fake-login-security.com"
    res_phish = loader.predict_phishing(phishing_sample)
    
    assert "label" in res_phish
    assert "confidence" in res_phish
    assert res_phish["label"] == "phishing"
    assert res_phish["confidence"] > 0.8

    benign_sample = "Please find attached the updated schedule for tomorrow's team sync."
    res_benign = loader.predict_phishing(benign_sample)
    
    assert "label" in res_benign
    assert "confidence" in res_benign
    assert res_benign["label"] == "benign"
    assert res_benign["confidence"] > 0.8
