FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend .

# Create directory for database with proper permissions
RUN mkdir -p /app/data && chmod 777 /app/data

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]