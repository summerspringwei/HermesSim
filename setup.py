#!/usr/bin/env python3
"""Setup script for HermesSim package."""

from setuptools import setup, find_packages
import os

# Read the README file for long description
readme_path = os.path.join(os.path.dirname(__file__), "README.md")
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, "r", encoding="utf-8") as f:
        long_description = f.read()

# Read requirements
requirements_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
requirements = []
# if os.path.exists(requirements_path):
#     with open(requirements_path, "r", encoding="utf-8") as f:
#         requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="hermessim",
    version="0.1.0",
    description="Binary Code Similarity Detection using Semantics-Oriented Graph Representation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="SJTU NSSL Lab",
    url="https://github.com/sjtu-nssl/HermesSim",
    package_dir={"hermessim": "."},
    packages=["hermessim", "hermessim.e2e", "hermessim.lifting", "hermessim.preprocess", "hermessim.model", "hermessim.model.core"],
    python_requires=">=3.8",
    install_requires=requirements,
    include_package_data=True,
    package_data={
        "hermessim": [
            "bin/*.jar",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
    ],
)

