# Pocketful Stage 1

Build and run the standalone service:

```sh
docker build -t pocketful-stage1 .
docker run --rm -e PORT=8080 -p 8080:8080 pocketful-stage1
```

The service listens on `0.0.0.0`, uses in-memory state, and exposes `GET /health` for readiness. `POST /_test/reset`, `GET /_test/export`, and `POST /_test/import` are enabled without authentication as required.
