FROM python:3.11-slim

WORKDIR /app
RUN mkdir -p /app/config
COPY update_dyndns.py /app/update_dyndns.py
COPY config.example.yaml /app/config.example.yaml
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
RUN pip install requests pyyaml
ENTRYPOINT ["/app/entrypoint.sh"]