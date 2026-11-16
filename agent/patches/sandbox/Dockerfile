FROM python:3.12-slim

# Pytest is available offline at runtime; no network installation is needed
# inside the restricted sandbox container.
RUN pip install --no-cache-dir pytest

WORKDIR /workspace
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["python", "--version"]
