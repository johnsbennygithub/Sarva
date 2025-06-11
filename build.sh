#!/usr/bin/env bash
# exit on error
set -o errexit

# Install Python dependencies
pip install -r requirements.txt

# Initialize the database
python << 'END'
from app import init_db
init_db()
END 