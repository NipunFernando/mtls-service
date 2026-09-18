# Stdlib-only service: no pip install step, nothing to pin.
FROM python:3.12-slim

# Choreo requires the container to run as a non-root user with a numeric UID
# in the 10000-20000 range.
ARG UID=10014
ARG GID=10014

RUN groupadd -g "$GID" appuser && useradd -m -u "$UID" -g "$GID" appuser

WORKDIR /app
COPY main.py config.py certinfo.py ./

USER $UID:$GID

ENV PYTHONUNBUFFERED=1 \
    MTLS_PORT=8443 \
    HEALTH_PORT=8080

EXPOSE 8443 8080

CMD ["python", "main.py"]
