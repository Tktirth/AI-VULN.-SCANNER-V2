# Base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STREAMLIT_SERVER_PORT=8080 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0

# Create a non-root user and group
RUN groupadd -r scanner_user && useradd -r -g scanner_user scanner_user

# Set working directory
WORKDIR /app

# Install system dependencies required for compiling Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    g++ \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Change ownership of the app directory to the non-root user
RUN chown -R scanner_user:scanner_user /app

# Switch to the non-root user
USER scanner_user

# Expose Streamlit port
EXPOSE 8080

# Healthcheck to verify the app is running
HEALTHCHECK CMD curl --fail http://localhost:8080/_stcore/health || exit 1

# Command to run the application
CMD ["streamlit", "run", "app.py"]
