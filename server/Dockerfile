# Stdlib-only service: no pip install step, nothing to pin.
FROM python:3.12-slim

# Choreo requires the container to run as a non-root user with a numeric UID in
# the 10000-20000 range, and its Checkov scan (CKV_CHOREO_1) reads the USER
# directive statically -- so the UID is written out literally here rather than
# passed through an ARG, which the scanner cannot resolve.
RUN groupadd -g 10014 appuser && useradd -m -u 10014 -g 10014 appuser

WORKDIR /app
COPY main.py config.py certinfo.py ./

USER 10014

ENV PYTHONUNBUFFERED=1 \
    MTLS_PORT=8443 \
    HEALTH_PORT=8080

EXPOSE 8443 8080

CMD ["python", "main.py"]
