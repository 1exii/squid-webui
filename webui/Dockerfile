FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY traffic_analytics.py .
COPY activity_reports.py .
COPY config_audit.py .
COPY templates/ templates/
COPY static/ static/

# Environment defaults
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py

EXPOSE 3131

# Single worker on purpose: app.py performs singleton startup work (compiling
# rules.acl and SIGHUPing Squid) and runs background policy-expiry and activity-
# archive threads. Multiple workers would race on the generated runtime files.
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${WEBUI_PORT:-3131} --workers 1 --threads 4 --timeout 120 app:app"]
