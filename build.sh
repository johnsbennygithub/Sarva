#!/usr/bin/env bash
# exit on error
set -o errexit

# Install Python dependencies
pip install -r requirements.txt

# Create data directory if it doesn't exist
mkdir -p /data

# Set proper permissions
chmod 777 /data

# Initialize the database
python << END
from app import init_db
init_db()
END 