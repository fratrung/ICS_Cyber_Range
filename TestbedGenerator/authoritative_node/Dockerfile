FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt requirements.txt
COPY did_iiot_dht did_iiot_dht

RUN pip install --no-cache-dir -r requirements.txt


EXPOSE 5007
EXPOSE 5000

CMD ["python", "did_iiot_dht/authoritative_node.py"]