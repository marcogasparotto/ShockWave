"""Shockwave - Network Diagnostic Toolkit setup."""

from setuptools import setup, find_packages

setup(
    name="shockwave",
    version="0.1.0",
    description="Shockwave - Network Diagnostic Toolkit",
    author="Decepticon Intelligence Unit",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "shockwave=shockwave.__main__:main",
        ],
    },
)
