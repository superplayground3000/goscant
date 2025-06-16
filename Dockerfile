# syntax=docker/dockerfile:1
FROM ubuntu:22.04 as builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends golang-go ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN go build -o goscant main.go

# Final image
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/goscant /usr/local/bin/goscant
COPY --from=builder /app/config /app/config
COPY --from=builder /app/internal /app/internal
COPY --from=builder /app/pkg /app/pkg
COPY --from=builder /app/go.mod /app/go.mod
COPY --from=builder /app/go.sum /app/go.sum

ENTRYPOINT ["/usr/local/bin/goscant"] 