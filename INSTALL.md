# Installing HermesSim as a Python Package

To make HermesSim importable as `hermessim` in other Python projects, install it in development mode:

## Installation

From the project root directory (`/data1/xiachunwei/Projects/HermesSim`), run:

```bash
pip install -e .
```

This installs the package in "editable" mode, so changes to the source code are immediately reflected.

## Usage

After installation, you can import HermesSim in other Python projects:

```python
from hermessim import HersemSimEmbedding

# Or import specific modules
from hermessim.e2e import HersemSimEmbedding
from hermessim.lifting import pcode_lifter
from hermessim.preprocess import preprocessing_pcode
from hermessim.model.core import GNNModel
```

## Requirements

Make sure you have:
- Python 3.8 or higher
- All dependencies from `requirements.txt` installed
- `GHIDRA_HOME` environment variable set (if using Ghidra features)
- The `bin/gsat-1.0.jar` file in the project directory

## Note

The package structure uses `package_dir` mapping, so the package name `hermessim` maps to the current directory structure. This allows importing as `hermessim.e2e`, `hermessim.lifting`, etc. without renaming directories.

