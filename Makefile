# K6 Blockchain Benchmark

BUILD_DIR = build
K6_OUTPUT = $(BUILD_DIR)/k6
GO_SRCS := $(shell find xk6-ethereum xk6-queue -name "*.go" -o -name "go.mod" -o -name "go.sum")
export COMMIT := $(shell git rev-parse --short HEAD)
TEST_FLAGS ?=

.PHONY: all
all: build

.PHONY: setup
setup:
	@echo "Setting up..."
	@GIT_LFS_SKIP_SMUDGE=1 git submodule update --init --recursive
	@go install go.k6.io/xk6/cmd/xk6@latest
	@cd contracts && bash scripts/setup-gateway-addresses.sh

.PHONY: build
build: $(K6_OUTPUT)

$(K6_OUTPUT): $(GO_SRCS)
	@echo "Building custom k6 binary..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && GOWORK=off xk6 build \
		--with xk6-ethereum=$(abspath ./xk6-ethereum) \
		--with xk6-queue=$(abspath ./xk6-queue) \
		--with github.com/grafana/xk6-output-influxdb \
		--replace github.com/ethereum/go-ethereum=github.com/OffchainLabs/go-ethereum@v0.0.0-20251126100423-ae34a6a9ef5a \
		-v

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)

.PHONY: build-contracts
build-contracts:
	@echo "Setting up contract dependencies..."
	@cd contracts && bash scripts/setup-gateway-addresses.sh
	@echo "Compiling Foundry contracts..."
	@cd contracts && forge build

.PHONY: test-unit
test-unit:
	@go test $(TEST_FLAGS) ./xk6-ethereum

.PHONY: test-integration
test-integration:
	@go test -tags=integration $(TEST_FLAGS) ./xk6-ethereum

# ==============================================================================
# Scenarios
# ==============================================================================

.PHONY: run-eth-transfer
run-eth-transfer: build
	@set -a && . ./.env && set +a && $(K6_OUTPUT) run --out json=tmp.json --out xk6-influxdb scripts/eth-rate.ts

.PHONY: run-erc20
run-erc20-transfer: build build-contracts
	@set -a && . ./.env && set +a && $(K6_OUTPUT) run --out json=tmp.json --out xk6-influxdb scripts/erc20-rate.ts

.PHONY: run-arbitrary-execution
run-arbitrary-execution: build build-contracts
	@set -a && . ./.env && set +a && \
	N_SSTORE=$(N_SSTORE) N_EVENTS=$(N_EVENTS) CALLDATA_SIZE=$(CALLDATA_SIZE) \
	$(K6_OUTPUT) run --out json=tmp.json --out xk6-influxdb scripts/arbitrary-execution.ts

.PHONY: run-user-decrypt-response
run-user-decrypt-response: build build-contracts
	@set -a && . ./.env && set +a && $(K6_OUTPUT) run --out json=tmp.json --out xk6-influxdb scripts/user-decrypt-response.ts

.PHONY: run-public-decrypt-response
run-public-decrypt-response: build build-contracts
	@set -a && . ./.env && set +a && $(K6_OUTPUT) run --out json=tmp.json --out xk6-influxdb scripts/public-decrypt-response.ts

.PHONY: run-public-decrypt-flow
run-public-decrypt-flow: build build-contracts
	@set -a && . ./.env && set +a && $(K6_OUTPUT) run --out json=tmp.json --out xk6-influxdb scripts/public-decrypt-flow.ts

.PHONY: run-user-decrypt-flow
run-user-decrypt-flow: build build-contracts
	@set -a && . ./.env && set +a && $(K6_OUTPUT) run --out json=tmp.json --out xk6-influxdb scripts/user-decrypt-flow.ts

.PHONY: run-allow-public-decrypt
run-allow-public-decrypt: build build-contracts
	@set -a && . ./.env && set +a && \
	$(K6_OUTPUT) run --out json=tmp.json --out xk6-influxdb scripts/allow-public-decrypt.ts

.PHONY: refund
refund:
	@set -a && . ./.env && set +a && bun run refund

monitoring: build
	@set -a && . ./.env && set +a && $(K6_OUTPUT) run --out json=tmp.json --out xk6-influxdb scripts/monitoring.ts

.PHONY: run-historical-monitoring
run-historical-monitoring: build
	@if [ -z "$(START_BLOCK)" ]; then \
		echo "Error: START_BLOCK is required"; \
		echo "Usage: START_BLOCK=1000 END_BLOCK=2000 NUM_VUS=4 make run-historical-monitoring"; \
		exit 1; \
	fi
	@set -a && . ./.env && set +a && \
	START_BLOCK=$(START_BLOCK) END_BLOCK=$(END_BLOCK) BATCH_SIZE=$(BATCH_SIZE) LOG_INTERVAL=$(LOG_INTERVAL) NUM_VUS=$(NUM_VUS) \
	$(K6_OUTPUT) run --out json=tmp.json --out xk6-influxdb scripts/historical-monitoring.ts

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build                      - Build custom k6 binary"
	@echo "  clean                      - Clean build artifacts"
	@echo "  run-public-decrypt-flow      - Run public decryption request benchmark (DecryptionMockV2)"
	@echo "  run-user-decrypt-flow        - Run user decryption request benchmark (DecryptionMockV2)"
	@echo "  run-user-decrypt-response    - Run user decrypt response-only benchmark (DecryptionMock)"
	@echo "  run-public-decrypt-response  - Run public decrypt response-only benchmark (DecryptionMock)"
	@echo "  run-allow-public-decrypt     - Run allowPublicDecrypt benchmark"
	@echo "  run-eth-transfer           - Run ETH transfer benchmark"
	@echo "  run-erc20                  - Run ERC20 transfer benchmark (deploys ERC20 in setup, sync tx)"
	@echo "  run-arbitrary-execution    - Run arbitrary execution benchmark (N_SSTORE, N_EVENTS, or CALLDATA_SIZE)"
	@echo "  run-historical-monitoring  - Run historical block monitoring (START_BLOCK required, NUM_VUS=4 default)"
	@echo "  refund                     - Refund ETH from test accounts (fast, uses bun+viem)"
	@echo "  test-unit                  - Run Go unit tests (no node required)"
	@echo "  test-integration           - Run Go integration tests (requires Anvil at 127.0.0.1:8545)"
	@echo "  help                       - Show this help"
