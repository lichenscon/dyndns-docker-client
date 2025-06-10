FROM python:3.11-slim

WORKDIR /app
COPY update_dyndns.py /app/update_dyndns.py
COPY config.yaml /app/config.yaml
RUN pip install requests pyyaml

CMD ["python", "update_dyndns.py"]