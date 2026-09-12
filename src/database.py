"""
Database operations for Guardian Agent — re-exports core implementation.

The canonical implementation lives in src/core/database.py with duplicate-safe
INSERT OR IGNORE, connection context manager, and indexed tables.
"""

from src.core.database import Database

__all__ = ['Database']
