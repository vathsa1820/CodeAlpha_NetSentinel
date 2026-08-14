"""
NetSentinel — Vercel Serverless Function Entry Point
"""

import os
import sys

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app import app

# Export app for Vercel Python serverless runtime
__all__ = ["app"]
