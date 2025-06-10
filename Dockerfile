FROM python:3.11-slim

WORKDIR /app
COPY update_dyndns.py /app/update_dyndns.py
RUN pip install requests

CMD ["python", "update_dyndns.py"]
