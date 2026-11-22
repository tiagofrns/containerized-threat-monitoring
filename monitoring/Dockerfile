FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin app
COPY health_exporter.py resource_exporter.py client.py /app/
USER app
CMD ["python", "/app/health_exporter.py"]
