FROM python:3.13-slim

WORKDIR /app

COPY app /app/app
COPY run.py /app/run.py

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 80

CMD ["python", "run.py"]