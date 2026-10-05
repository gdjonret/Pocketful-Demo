# Pocketful Stage 2

Build and run the standalone service:

```sh
docker build -t pocketful-stage2 .
docker run --rm --network none -e PORT=8080 -p 8080:8080 pocketful-stage2
```

The self-contained service listens on `0.0.0.0`, serves the API and browser UI, uses in-memory state, and exposes `GET /health` for readiness. It needs no runtime network access. `POST /_test/reset`, `GET /_test/export`, and `POST /_test/import` are enabled without authentication as required.
