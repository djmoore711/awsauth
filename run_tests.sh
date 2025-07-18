#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Activate the virtual environment
source .venv/bin/activate

# Add the project root to PYTHONPATH to allow imports
export PYTHONPATH=$(pwd)

echo "Running automated tests with pytest..."

# Run pytest
pytest

echo "All automated tests passed successfully!"
