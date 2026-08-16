FROM golang:1.21-alpine AS builder

RUN apk add --no-cache gcc musl-dev make

WORKDIR /build

COPY gateway/go_gateway/go.mod gateway/go_gateway/go.sum ./gateway/go_gateway/
RUN cd gateway/go_gateway && go mod download

COPY gateway/go_gateway ./gateway/go_gateway
RUN cd gateway/go_gateway && go build -o /out/gateway .

COPY control-plane/go_core/go.mod control-plane/go_core/go.sum ./control-plane/go_core/
RUN cd control-plane/go_core && go mod download

COPY control-plane/go_core ./control-plane/go_core
RUN cd control-plane/go_core && go build -o /out/control_plane .

COPY gateway/nats_bus/go.mod gateway/nats_bus/go.sum ./gateway/nats_bus/
RUN cd gateway/nats_bus && go mod download

COPY gateway/nats_bus ./gateway/nats_bus
RUN cd gateway/nats_bus && go build -o /out/nats_bus .

COPY control-plane/compiler_worker/go.mod ./control-plane/compiler_worker/
COPY control-plane/compiler_worker ./control-plane/compiler_worker
RUN cd control-plane/compiler_worker && go build -o /out/compiler_worker .

FROM alpine:3.19

RUN apk add --no-cache ca-certificates nats-server tzdata

WORKDIR /app
COPY --from=builder /out/* /app/
COPY certs/ /app/certs/

EXPOSE 4433 4222 8222

CMD ["/app/gateway", "-listen", ":4433", "-nats", "nats://nats:4222"]
