FROM python:3.10-slim

WORKDIR /app

# Install system dependencies (needed for mysql client sometimes)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libcairo2-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium browser for APEX Crawler
RUN playwright install --with-deps chromium

COPY apex-dynamic-service /app

# Expose port (FastAPI default)
EXPOSE 8000

# Run commands
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
