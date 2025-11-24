FROM --platform=linux/amd64 python:3.12-slim
LABEL description="Source Checker 0.4.5"

USER 0
ENV APP_DIR=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ARG APP_USER="appuser"
ARG APP_GROUP="appuser"

COPY . ${APP_DIR}

WORKDIR ${APP_DIR}

RUN set -x && groupadd "$APP_GROUP" && \
    useradd --comment "Flask user"  \
    --home-dir "$APP_DIR"  \
    --create-home  \
    --system  \
    --gid "$APP_GROUP" "$APP_USER" && \
    chown -R appuser:appuser ${APP_DIR} && \
    chmod -R 755 ${APP_DIR} && \
    pip3 install -r /app/requirements.txt && \
    mkdir ~/coldcache && \
    chmod 755 ~/coldcache && \
    apt update -y && apt upgrade -y

USER appuser
ENTRYPOINT ["python3"]
CMD ["app.py"]
EXPOSE 8000
