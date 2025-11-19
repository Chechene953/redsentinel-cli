#!/usr/bin/env python3
"""
RedSentinel - Launcher Script
Quick launcher for development/testing
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from redsentinel.cli_main import main

if __name__ == '__main__':
    main()

