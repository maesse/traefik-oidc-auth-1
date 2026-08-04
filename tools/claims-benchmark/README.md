# Claims benchmark

This project compares the current JSONPath-based authorization check with a direct top-level claim lookup and RS256 JWT validation:

- Native Go microbenchmarks run the extracted functions directly.
- The Traefik benchmark loads the same functions as a local plugin, so they execute through Traefik's Yaegi runtime.

The hardcoded claims contain a realistic `groups` array, and the assertion accepts either `admins` or `owners`.

## Native benchmark

```sh
go test -run '^$' -bench . -benchmem -benchtime 3s -count 5
```

## Traefik/Yaegi benchmark

Vendor dependencies first:

```sh
go mod vendor
```

Start an isolated Traefik container from the repository root:

```sh
docker run --rm --name claims-benchmark-traefik \
  -p 127.0.0.1:18080:8080 \
  -v "$PWD/tools/claims-benchmark:/plugins-local/src/example.com/claimbench:ro" \
  -v "$PWD/tools/claims-benchmark:/benchmark:ro" \
  traefik:v3.7 \
  --configFile=/benchmark/traefik.yml
```

Run the sequential keep-alive load generator:

```sh
go run ./cmd/loadgen -url http://127.0.0.1:18080 -n 5000 -warmup 200
```

Subtract the `baseline` result from the other modes to estimate the incremental Yaegi cost.
