"""
WSGI configuration for PythonAnywhere deployment

This file is used by PythonAnywhere to run the Flask application.
Configure this file in the PythonAnywhere Web tab under "WSGI configuration file".
"""

import sys
import os

# Add project directory to path
# Replace YOUR_USERNAME with your PythonAnywhere username
project_home = "/home/YOUR_USERNAME/meow-decoder"
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Add web_demo directory to path
web_demo_dir = os.path.join(project_home, "web_demo")
if web_demo_dir not in sys.path:
    sys.path.insert(0, web_demo_dir)

# Set working directory to web_demo
os.chdir(web_demo_dir)

# Import Flask app
from app import app as application

# Optional: Configure production settings
application.config["DEBUG"] = False
application.config["TESTING"] = False

# Optional: Set custom secret key from environment variable
# application.secret_key = os.environ.get('FLASK_SECRET_KEY', application.secret_key)
