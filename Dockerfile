FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir --upgrade pip build \
    && python -m build --wheel --outdir /dist

FROM python:3.12-slim

# Run as a non-root user; the app only needs outbound SSH/WinRM + the API server.
RUN useradd --system --uid 1001 --create-home publisher

COPY --from=build /dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

USER 1001
ENTRYPOINT ["cert-publisher"]
