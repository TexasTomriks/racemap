"""LLM triage layer: false-positive reduction only — never exploit generation."""

from .backends import BACKEND_CLASSES, LLM_CHOICES
from .pipeline import TriagePipeline

__all__ = ["TriagePipeline", "BACKEND_CLASSES", "LLM_CHOICES"]
