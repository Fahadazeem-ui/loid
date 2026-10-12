"""
fsengine — evidence-based, deep-reading file & archive classifier.

Design in one paragraph
-----------------------
Nothing is decided by the *first* matching rule. Every detector contributes
weighted evidence and a fusion layer combines it into a ranked hypothesis with
an explicit confidence and margin. Reading happens in *stages* (cheap first:
name -> header -> archive listing -> marker files -> content scan -> bytecode /
binary metadata -> nested archives) and the classifier stops as soon as the
evidence is unambiguous, so it stays fast on easy files and only goes deep on
genuinely ambiguous ones.

Public API:
    from fsengine import Classifier, Config
    decision = Classifier(Config()).classify(Path("something.zip"))
"""

from .model import Config, Decision, Taxonomy, Evidence, TAXONOMY  # noqa: F401
from .facts import Facts  # noqa: F401
from .classify import Classifier  # noqa: F401

__all__ = ["Classifier", "Config", "Decision", "Facts", "Taxonomy", "Evidence", "TAXONOMY"]
__version__ = "2.0.0"
