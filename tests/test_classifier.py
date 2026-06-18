from src.core.classifier import Classifier
from src.models.enums import AppType


def test_classifier_maps_known_domains():
    assert Classifier.classify("www.facebook.com") == AppType.FACEBOOK
    assert Classifier.classify("youtube.com") == AppType.YOUTUBE
    assert Classifier.classify("github.com") == AppType.GITHUB


def test_classifier_returns_unknown_for_missing_domain():
    assert Classifier.classify(None) == AppType.UNKNOWN
    assert Classifier.classify("example.org") == AppType.UNKNOWN
