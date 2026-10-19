FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium \
    && useradd --create-home --shell /usr/sbin/nologin websentinel \
    && chown -R websentinel:websentinel /ms-playwright /app

COPY --chown=websentinel:websentinel . .

USER websentinel

EXPOSE 9000

CMD ["python", "-m", "app"]
