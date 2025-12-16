#!/bin/bash

# CI Smoke Test Suite for Blockchain Benchmarks
# Tests various benchmark scripts with short duration and low load to verify stability

echo "🧪 Starting CI Smoke Test Suite"
echo "================================"

# Common smoke test parameters
# Allow overriding from environment, default to minimal values for smoke testing
export DURATION="${DURATION:-2}"
export RATE="${RATE:-5}"
export MAX_VUS="${MAX_VUS:-30}"
export PREALLOCATED_VUS="${PREALLOCATED_VUS:-10}"
export ETH_RPC_URL="${ETH_RPC_URL:-http://127.0.0.1:8545}"
export MNEMONIC="${MNEMONIC:-test test test test test test test test test test test junk}"
export ANVIL_PORT="${ANVIL_PORT:-8545}"
export ANVIL_BLOCK_TIME="${ANVIL_BLOCK_TIME:-0.2}"
export ANVIL_GAS_PRICE="${ANVIL_GAS_PRICE:-1}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track test results
PASSED=0
FAILED=0
FAILED_TESTS=()

start_anvil() {
	local log_file="$1"
	anvil --port "${ANVIL_PORT}" --block-time "${ANVIL_BLOCK_TIME}" --gas-price "${ANVIL_GAS_PRICE}" \
		>"${log_file}" 2>&1 &
	echo $!
}

wait_for_anvil() {
	echo "Waiting for Anvil HTTP RPC to be ready..."
	for i in {1..30}; do
		if curl -s -X POST -H "Content-Type: application/json" \
			--data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
			"http://127.0.0.1:${ANVIL_PORT}" >/dev/null 2>&1; then
			return 0
		fi
		echo "Waiting for Anvil... (${i}/30)"
		sleep 0.2
	done
	return 1
}

wait_for_websocket() {
	echo "Waiting for WebSocket to be ready..."
	for i in {1..15}; do
		if cast rpc eth_blockNumber --rpc-url "ws://127.0.0.1:${ANVIL_PORT}" >/dev/null 2>&1; then
			echo "WebSocket is responding at ws://127.0.0.1:${ANVIL_PORT}"
			# Verify it's stable with a second check
			sleep 0.2
			if cast rpc eth_blockNumber --rpc-url "ws://127.0.0.1:${ANVIL_PORT}" >/dev/null 2>&1; then
				echo "WebSocket connection verified and stable"
				return 0
			fi
		fi
		echo "Waiting for WebSocket... (${i}/15)"
		sleep 0.2
	done
	echo "WebSocket did not become ready in time"
	return 1
}

# Function to run a test
run_test() {
	local test_name="$1"
	local script="$2"
	local extra_args="$3"

	echo ""
	echo -e "${YELLOW}Running: ${test_name}${NC}"
	echo "Script: ${script}"
	echo "Args: ${extra_args}"

	local anvil_log
	anvil_log=$(mktemp -t anvil-log-XXXXXX)
	local anvil_pid
	anvil_pid=$(
		set -e
		start_anvil "${anvil_log}"
	)
	# shellcheck disable=SC2329
	cleanup_anvil() {
		if [[ -n ${anvil_pid} ]]; then
			kill "${anvil_pid}" >/dev/null 2>&1 || true
		fi
		rm -f "${anvil_log}"
	}
	trap cleanup_anvil RETURN

	# shellcheck disable=SC2310
	if ! wait_for_anvil; then
		echo -e "${RED}Failed to start Anvil for ${test_name}${NC}"
		cat "${anvil_log}"
		FAILED_TESTS+=("${test_name} (Anvil startup)")
		((FAILED += 1))
		return
	fi

	# shellcheck disable=SC2310
	if ! wait_for_websocket; then
		echo -e "${RED}WebSocket not ready for ${test_name}${NC}"
		cat "${anvil_log}"
		FAILED_TESTS+=("${test_name} (WebSocket readiness)")
		((FAILED += 1))
		return
	fi

	# Construct command with environment variables
	local cmd="env DURATION=\"${DURATION}\" RATE=${RATE} MAX_VUS=${MAX_VUS} PREALLOCATED_VUS=${PREALLOCATED_VUS} ETH_RPC_URL=\"http://127.0.0.1:${ANVIL_PORT}\" MNEMONIC=\"${MNEMONIC}\" ${extra_args} ./build/k6 run \"${script}\""

	# Stream output live
	local tmp_log
	tmp_log=$(mktemp -t k6-smoke-log-XXXXXX)
	set +e
	eval "${cmd}" 2>&1 | tee "${tmp_log}" || true
	local exit_code=${PIPESTATUS[0]}
	set -e

	# Check if command succeeded and output doesn't contain `ERRO[` or `Error`
	if [[ ${exit_code} -eq 0 ]] && ! grep -q "ERRO\[" "${tmp_log}" && ! grep -q "Error" "${tmp_log}"; then
		echo -e "${GREEN}✓ PASSED${NC}"
		((PASSED += 1))
	else
		echo -e "${RED}✗ FAILED${NC}"
		((FAILED += 1))
		FAILED_TESTS+=("${test_name}")
	fi

	rm -f "${tmp_log}"
}

# Define tests as "Name|Script|Args"
declare -a tests=(
	"ERC20 Transfer (Smoke, Batch=1)|scripts/erc20-rate.ts|BATCH_SIZE=1"
	"ERC20 Transfer (Smoke, Batch=5)|scripts/erc20-rate.ts|BATCH_SIZE=5"
	"ETH Transfer (Smoke, Batch=1)|scripts/eth-rate.ts|BATCH_SIZE=1"
	"ETH Transfer (Smoke, Batch=5)|scripts/eth-rate.ts|BATCH_SIZE=5"
	"Arbitrary Execution SSTORE (Smoke, Batch=1)|scripts/arbitrary-execution.ts|N_SSTORE=10 BATCH_SIZE=1"
	"Arbitrary Execution SSTORE (Smoke, Batch=5)|scripts/arbitrary-execution.ts|N_SSTORE=10 BATCH_SIZE=5"
	"Arbitrary Execution Events (Smoke, Batch=1)|scripts/arbitrary-execution.ts|N_EVENTS=100 BATCH_SIZE=1"
	"Arbitrary Execution Calldata (Smoke, Batch=1)|scripts/arbitrary-execution.ts|CALLDATA_SIZE=1000 BATCH_SIZE=1"
	"Arbitrary Execution Burn Gas (Smoke, Batch=1)|scripts/arbitrary-execution.ts|BURN_GAS=10000 BATCH_SIZE=1"
	"User Decrypt (Smoke, Batch=1)|scripts/user-decrypt.ts|BATCH_SIZE=1 CONSENSUS_THRESHOLD=2 PAYLOAD_SIZE_BYTES=64"
	"User Decrypt (Smoke, Batch=3)|scripts/user-decrypt.ts|BATCH_SIZE=3 CONSENSUS_THRESHOLD=2 PAYLOAD_SIZE_BYTES=64"
	"Allow Public Decrypt (Smoke, Batch=1)|scripts/allow-public-decrypt.ts|BATCH_SIZE=1 CONSENSUS_THRESHOLD=2"
	"Allow Public Decrypt (Smoke, Batch=3)|scripts/allow-public-decrypt.ts|BATCH_SIZE=3 CONSENSUS_THRESHOLD=2"
)

# Loop through tests
for test_config in "${tests[@]}"; do
	# Split string by |
	IFS='|' read -r name script args <<<"${test_config}"
	run_test "${name}" "${script}" "${args}"
done

# Print summary
echo ""
echo "================================"
echo "🧪 Smoke Test Suite Complete"
echo "================================"
echo -e "${GREEN}Passed: ${PASSED}${NC}"
echo -e "${RED}Failed: ${FAILED}${NC}"

if [[ ${FAILED} -gt 0 ]]; then
	echo ""
	echo "Failed tests:"
	for test in "${FAILED_TESTS[@]}"; do
		echo -e "  ${RED}✗${NC} ${test}"
	done
	exit 1
else
	echo ""
	echo -e "${GREEN}All tests passed!${NC}"
	exit 0
fi
