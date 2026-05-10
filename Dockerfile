FROM python:3.13-slim

WORKDIR /app

COPY app /app/app
COPY run.py /app/run.py

# If SSL/TLS is enabled, the certificate and key files must be copied into the container.
# COPY cert.pem /etc/ssl/certs/cert.pem
# COPY key.pem /etc/ssl/private/key.pem

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 80 443

CMD ["python", "run.py"]