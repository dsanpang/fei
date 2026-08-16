.PHONY: all certs gateway control-plane nats-bus compiler-worker test docker clean

ROOT := $(shell pwd)
BIN := $(ROOT)/bin

all: certs gateway control-plane nats-bus compiler-worker test

$(BIN):
	mkdir -p $(BIN)

certs: $(BIN)
	cd tools/certgen && go build -o $(BIN)/certgen .
	@test -f certs/psk.bin || $(BIN)/certgen certs

gateway: $(BIN) certs
	cd gateway/go_gateway && go build -o $(BIN)/gateway .

control-plane: $(BIN)
	cd control-plane/go_core && go build -o $(BIN)/control_plane .

nats-bus: $(BIN)
	cd gateway/nats_bus && go build -o $(BIN)/nats_bus .

compiler-worker: $(BIN)
	cd control-plane/compiler_worker && go build -o $(BIN)/compiler_worker .

test:
	cd gateway/go_gateway && go test -v -count=1 ./...

docker:
	docker compose build
	docker compose up -d

docker-down:
	docker compose down

clean:
	rm -rf $(BIN)
	rm -f certs/*.pem certs/psk.bin
	docker compose down -v --rmi local 2>/dev/null || true

run-dev: certs
	@echo "Starting NATS..."
	@nats-server -p 4222 > /tmp/nats.log 2>&1 & echo $$! > /tmp/nats.pid
	@sleep 1
	@echo "Starting control-plane..."
	@$(BIN)/control_plane > /tmp/cp.log 2>&1 & echo $$! > /tmp/cp.pid
	@echo "Starting nats-bus..."
	@$(BIN)/nats_bus > /tmp/bus.log 2>&1 & echo $$! > /tmp/bus.pid
	@echo "Starting gateway..."
	@$(BIN)/gateway -cert certs/server-cert.pem -key certs/server-key.pem \
		-ca certs/ca-cert.pem -psk certs/psk.bin > /tmp/gw.log 2>&1 & echo $$! > /tmp/gw.pid
	@echo "All services started. PIDs in /tmp/*.pid"

stop-dev:
	@for f in /tmp/nats.pid /tmp/cp.pid /tmp/bus.pid /tmp/gw.pid; do \
		[ -f $$f ] && kill $$(cat $$f) 2>/dev/null && rm -f $$f || true; \
	done
	@echo "All services stopped"
