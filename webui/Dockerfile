FROM python:3.11-slim

WORKDIR /app

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

# Single worker on purpose: app.py performs singleton startup work (compiling
# rules.acl and SIGHUPing Squid) and runs a background expiry thread. Multiple
# workers would each do both, racing on the generated ACL files.
CMD ["gunicorn", "--bind", "0.0.0.0:3131", "--workers", "1", "--threads", "4", "--timeout", "120", "app:app"]
