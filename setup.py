#!/usr/bin/env python3
"""
PENTRA-X Setup Script
Install with: pip install -e .
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding='utf-8') if readme_path.exists() else ""

setup(
    name="pentrax",
    version="2.0.0",
    author="0xP4X",
    author_email="",
    description="Advanced Pentesting Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/0xP4X/pentra-x",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[
        "pycryptodome>=3.19.0",
        "PyYAML>=6.0",
        "requests>=2.31.0",
    ],
    extras_require={
        "full": [
            "scapy",
            "shodan",
            "python-nmap",
        ],
    },
    entry_points={
        "console_scripts": [
            "pentrax=pentrax.__main__:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
