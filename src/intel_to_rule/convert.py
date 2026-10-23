"""Sigma -> Splunk SPL / Elastic Lucene via pySigma. Needs the 'sigma' extra.

Field mapping is environment specific. Real deployments add their own pipelines in config/pipeline.yaml.
"""
from __future__ import annotations


def available() -> bool:
    try:
        import sigma.backends.elasticsearch  # noqa: F401
        import sigma.backends.splunk  # noqa: F401
    except ImportError:
        return False
    return True


def convert(sigma_text: str) -> dict[str, str]:
    """Return {"splunk": ..., "elastic": ...} queries for a Sigma rule."""
    from sigma.backends.elasticsearch import LuceneBackend
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection

    collection = SigmaCollection.from_yaml(sigma_text)
    return {
        "splunk": "\n".join(SplunkBackend().convert(collection)),
        "elastic": "\n".join(LuceneBackend().convert(collection)),
    }
