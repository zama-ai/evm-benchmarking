import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.2/index.js";
import type { Call3Value } from "k6/x/ethereum";
import { initializeClient, maybeDeployMulticall3 } from "../helpers/init.ts";
import { monitoringLoop } from "../helpers/monitoring.ts";
import { CONFIG, getScenarios } from "../helpers/scenarios.ts";

// Transfer amount (ether). Default 1000 wei.
const VALUE_WEI = 1000;

export const options = getScenarios("eth-transfer");

const vuClient = initializeClient();
const RECIPIENT = vuClient.getWallet().address;

interface SetupData {
	gasPrice: number;
	multicall_address: string | null;
}

export function setup(): SetupData {
	return {
		gasPrice: vuClient.gasPrice(),
		multicall_address: maybeDeployMulticall3(vuClient),
	};
}

export default function ({ gasPrice, multicall_address }: SetupData) {
	if (CONFIG.batchSize > 1 && multicall_address) {
		// Batch multiple transfers via Multicall3's aggregate3Value
		const calls: Call3Value[] = [];
		for (let i = 0; i < CONFIG.batchSize; i++) {
			calls.push({
				target: RECIPIENT,
				allowFailure: false,
				value: Number(VALUE_WEI),
				calldata: new Uint8Array(0), // Empty calldata for ETH transfer
			});
		}

		vuClient.batchCallValueSync(multicall_address, calls, {
			gasPrice: gasPrice,
		});
	} else {
		// Single transfer transaction
		const tx = {
			to: RECIPIENT,
			value: Number(VALUE_WEI),
			gasPrice: gasPrice,
		};
		vuClient.sendTransactionSync(tx);
	}
}

export function monitor() {
	monitoringLoop();
}

export function handleSummary(data: Record<string, unknown>) {
	return {
		stdout: textSummary(data, { indent: " ", enableColors: true }),
		"summary.json": JSON.stringify(data),
	};
}
