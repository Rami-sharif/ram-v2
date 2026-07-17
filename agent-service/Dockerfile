# Base image: slim official Python 3.12 build. Slim keeps the image small
# while still providing a full CPython (vs. alpine, which can break wheels
# for packages like psycopg/argon2-cffi that expect glibc).
FROM python:3.12-slim

# PYTHONUNBUFFERED=1: disable stdout/stderr buffering so log lines from
# uvicorn/the app appear immediately in `docker logs` instead of being
# batched, which matters for real-time debugging of a running SOC service.
# PYTHONDONTWRITEBYTECODE=1: skip writing .pyc files, keeping the container
# filesystem clean and avoiding stale bytecode in a throwaway image layer.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# All subsequent paths (COPY destinations, CMD) are relative to /app,
# which is where the application lives inside the container.
WORKDIR /app

# Install deps first for layer caching
# Copy only the dependency manifest first so Docker can cache the
# `pip install` layer; it only gets invalidated when requirements.txt
# actually changes, not on every app code edit.
COPY requirements.txt .
# Install Python dependencies. --no-cache-dir avoids storing pip's download
# cache in the image, keeping the final image smaller.
RUN pip install --no-cache-dir -r requirements.txt

# App code
# Copy the application source last so that code-only changes (the most
# frequent kind) don't bust the dependency-install cache layer above.
COPY app ./app

# Run as non-root
# Create a dedicated, unprivileged user (fixed uid so file ownership is
# predictable across rebuilds) rather than running the service as root,
# reducing blast radius if the container is ever compromised.
RUN useradd --create-home --uid 10001 appuser
# Switch the container's runtime user to the unprivileged account created
# above; all following instructions (and the running process) use it.
USER appuser

# Document that the service listens on port 8000 (FastAPI/uvicorn); this is
# metadata only — docker-compose.yml still does the actual host port mapping.
EXPOSE 8000

# Start the FastAPI app with uvicorn, binding to all interfaces (0.0.0.0) so
# it's reachable from other containers/host port mappings, on port 8000 to
# match EXPOSE above and the docker-compose port mapping.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
