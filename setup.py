#!/usr/bin/env python3

from setuptools import setup, find_packages
import sys
from pathlib import Path

# Ajouter le répertoire redsentinel au path pour importer la version
sys.path.insert(0, str(Path(__file__).parent))
from redsentinel.version import __version__

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="redsentinel",
    version=__version__,
    author="Alexandre Tavares - Redsentinel",
    description="Outil de sécurité professionnel pour la reconnaissance et le scan",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "redsentinel=redsentinel.cli_menu:main",
            "redsentinel-gui=redsentinel.gui:launch_gui",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
)

