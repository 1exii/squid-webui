FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Environment defaults
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py

EXPOSE 3131

CMD ["gunicorn", "--bind", "0.0.0.0:3131", "--workers", "2", "app:app"]
