FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY soc/ soc/
COPY config/ config/
COPY rules/ rules/
COPY playbooks/ playbooks/
COPY scenarios/ scenarios/

# run as an unprivileged user (the live Tetragon sensor overrides this)
RUN useradd -m -u 10001 soc && mkdir -p /app/evidence && chown -R soc /app
USER soc

EXPOSE 8080
CMD ["python", "-m", "soc.service", "dashboard"]
