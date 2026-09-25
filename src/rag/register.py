"""
Blueprint registration for Guardian RAG API.
"""

from __future__ import annotations

import logging
from flask import Flask

from src.rag.api import rag_bp

logger = logging.getLogger(__name__)


def register_rag(app: Flask) -> None:
    """Register RAG blueprint on the provided Flask app."""
    app.register_blueprint(rag_bp)
    logger.info("RAG blueprint registered at /api/v1/rag")
