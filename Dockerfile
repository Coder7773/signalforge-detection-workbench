FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SIGNALFORGE_DB=/data/signalforge.db SIGNALFORGE_READ_ONLY=true
WORKDIR /app
COPY app.py ./app.py
COPY static ./static
COPY data/demo_events.jsonl ./data/demo_events.jsonl
RUN mkdir -p /data && chown -R 10001:10001 /app /data
USER 10001:10001
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.getenv('PORT','8080'), timeout=2)" || exit 1
CMD ["python", "app.py", "--host", "0.0.0.0", "--demo"]
