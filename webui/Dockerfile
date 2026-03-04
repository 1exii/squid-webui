FROM python:3.11-slim

WORKDIR /app

# Install dependencies (including static docker client)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -sSL https://download.docker.com/linux/static/stable/x86_64/docker-24.0.9.tgz | tar -xz -C /tmp/ && \
    mv /tmp/docker/docker /usr/local/bin/ && \
    rm -rf /tmp/docker && \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY devices.list .
COPY templates/ templates/
COPY static/ static/

# Environment defaults
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py

EXPOSE 3131

CMD ["gunicorn", "--bind", "0.0.0.0:3131", "--workers", "2", "app:app"]
