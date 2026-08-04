# Benchmark results

Measured on 2026-08-04 with the project in this directory.

## Silver: native Go

Environment:

- Linux amd64
- Go 1.24.4
- CPU reported as `Intel Core Processor (Haswell, no TSX)`

Representative native results:

| Benchmark | Time per operation |
| --- | ---: |
| Marshal | 4.1-4.3 us |
| JSONPath selection | 10.9-12.6 us |
| Full JSONPath authorization | 12.6-14.6 us |
| Direct authorization | 0.37-0.40 us |

## Silver: Traefik/Yaegi

Environment:

- `traefik:v3.7` image, matching the deployed Traefik v3.7 line
- Local plugin loaded from the vendored source in this directory
- Sequential HTTP/1.1 requests over one keep-alive connection
- 200 warmup requests and 2,000 measured requests per mode
- Each middleware short-circuited with status 204, so no backend was involved

| Mode | p50 | Increment over baseline |
| --- | ---: | ---: |
| Baseline | 393.450 us | - |
| Marshal | 416.693 us | 23.243 us |
| JSONPath selection | 3,265.568 us | 2,872.118 us |
| Full JSONPath authorization | 3,440.525 us | 3,047.075 us |
| Direct authorization | 416.395 us | 22.945 us |
| RS256 JWT validation | 803.028 us | 409.578 us |
| RS256 JWT plus JSONPath authorization | 3,763.718 us | 3,370.268 us |

The small marshal/direct deltas are within run-to-run HTTP noise. The generic JSONPath path is the dominant isolated cost.

## Production comparison

The earlier sample of 100 authenticated Redis Insight requests showed a median Traefik `Overhead` of 9.123 ms. In this isolated benchmark:

- JSONPath authorization accounts for about 3.05 ms, or one-third of that median.
- JWT validation plus JSONPath authorization accounts for about 3.37 ms.
- Roughly 5.75 ms remains in other valid-session work and response handling that this focused benchmark intentionally does not model.

Likely remaining candidates include the interpreted Redis client and session JSON decode, cookie processing, JWKS lookup, header templates, and request sanitization. They require separate stage benchmarks or direct instrumentation before attributing the remaining time.
