FROM python:3.11-slim

WORKDIR /app
RUN mkdir -p /app/config
COPY update_dyndns.py /app/update_dyndns.py
COPY config.example.yaml /app/config/config.yaml
RUN pip install requests pyyaml

CMD ["python", "update_dyndns.py"]