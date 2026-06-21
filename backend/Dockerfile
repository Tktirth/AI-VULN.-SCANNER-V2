FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Create a non-root user and group
RUN groupadd -r scanner_user && useradd -r -g scanner_user scanner_user

# Set working directory
WORKDIR /app

# Install minimal dependencies (curl for health check)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files
COPY requirements.txt ./
COPY backend/requirements.txt ./backend/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt -r backend/requirements.txt

# Copy the entire workspace into /app
COPY . .

# Ensure the non-root user owns the files
RUN chown -R scanner_user:scanner_user /app

# Switch to the non-root user
USER scanner_user

# Expose FastAPI port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
