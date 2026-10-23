FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5000
# 1 solo worker para que el rate limiter cuente bien
CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:5000", "app:app"]
