# Meow Decoder - Docker image (headless demo + tools)
FROM python:3.11-slim

# System deps:
# - libzbar0: required by pyzbar (QR decode)
# - libgl1 / libglib2.0-0: often needed for opencv on slim images
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install python deps first (better caching)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the project
COPY . /app

# Default: run the Docker demo (writes outputs to /data)
ENV MEOW_DATA_DIR=/data
VOLUME ["/data"]

CMD ["python", "scripts/docker_demo.py"]
