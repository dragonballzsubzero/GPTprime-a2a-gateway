FROM python:3.13.9-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY broker-v03/worker/triage_worker.py /app/triage_worker.py
USER 65532:65532
ENTRYPOINT ["python", "-I", "-B", "/app/triage_worker.py", "/input/artifact"]
