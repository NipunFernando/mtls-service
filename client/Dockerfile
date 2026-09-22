# Stdlib-only client: no pip install step, nothing to pin.
FROM python:3.12-slim

# See the server Dockerfile: the UID is literal so Choreo's CKV_CHOREO_1 scan
# can read it.
RUN groupadd -g 10015 appuser && useradd -m -u 10015 -g 10015 appuser

WORKDIR /app
COPY main.py ./

USER 10015

ENV PYTHONUNBUFFERED=1 \
    CLIENT_MODE=once \
    HEALTH_PORT=8080

CMD ["python", "main.py"]
