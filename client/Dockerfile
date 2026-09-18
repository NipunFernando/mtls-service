# Stdlib-only client: no pip install step, nothing to pin.
FROM python:3.12-slim

ARG UID=10015
ARG GID=10015

RUN groupadd -g "$GID" appuser && useradd -m -u "$UID" -g "$GID" appuser

WORKDIR /app
COPY main.py ./

USER $UID:$GID

ENV PYTHONUNBUFFERED=1 \
    CLIENT_MODE=once \
    HEALTH_PORT=8080

CMD ["python", "main.py"]
