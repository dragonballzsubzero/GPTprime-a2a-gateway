# Build with a locally verified immutable base reference:
# docker build --build-arg BASE_IMAGE=python@sha256:<digest> ...
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY broker-v03/worker/triage_worker.py /app/triage_worker.py
COPY broker-v04/worker/triage_entry.py /app/triage_entry.py
USER 65534:65534
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1
ENTRYPOINT ["python", "-I", "-B", "/app/triage_entry.py"]
