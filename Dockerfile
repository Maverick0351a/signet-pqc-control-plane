
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --upgrade pip && pip install "uvicorn[standard]" && pip install -e /app
EXPOSE 8000
CMD ["uvicorn", "spcp.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
