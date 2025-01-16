FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt requirements.txt
COPY server.py server.py
COPY dilithium dilithium
COPY did_iiot_dht did_iiot_dht

RUN pip install --no-cache-dir -r requirements.txt


EXPOSE 5007

CMD ["python", "server.py"]
