import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.2/index.js";
import { initializeClient, maybeDeployMulticall3 } from "../helpers/init.ts";
import { monitoringLoop } from "../helpers/monitoring.ts";
import { CONFIG, getScenarios } from "../helpers/scenarios.ts";

// Contract details
const ARBITRARY_EXECUTION_ABI = String(
	open("../contracts/out/ArbitraryExecution.sol/ArbitraryExecution.abi.json"),
);
const ARBITRARY_EXECUTION_BIN = String(
	open("../contracts/out/ArbitraryExecution.sol/ArbitraryExecution.bin"),
);

// Workload config
const N_SSTORE = Number((__ENV.N_SSTORE as string) || "0");
const N_EVENTS = Number((__ENV.N_EVENTS as string) || "0");
const CALLDATA_SIZE = Number((__ENV.CALLDATA_SIZE as string) || "0");
const BURN_GAS = Number((__ENV.BURN_GAS as string) || "0");

// Validate that only one parameter is provided
const paramsSet = [
	N_SSTORE > 0,
	N_EVENTS > 0,
	CALLDATA_SIZE > 0,
	BURN_GAS > 0,
].filter(Boolean).length;
if (paramsSet !== 1) {
	throw new Error(
		"Exactly one of N_SSTORE, N_EVENTS, CALLDATA_SIZE, or BURN_GAS must be provided and greater than 0",
	);
}

export const options = getScenarios("arbitrary-execution");

const vuClient = initializeClient();

interface SetupData {
	shaperAddress: string;
	gasPrice: number;
	mode: "sstore" | "events" | "calldata" | "burnGas";
	value: number | string;
	multicall_address: string | null;
}

export function setup(): SetupData {
	// Deploy contract once
	const receipt = vuClient.deployContract(
		ARBITRARY_EXECUTION_ABI,
		ARBITRARY_EXECUTION_BIN,
	);
	const shaperAddress = String(receipt.contractAddress);
	const gasPrice = vuClient.gasPrice();

	// Determine which mode we're in and prepare the appropriate data
	let mode: "sstore" | "events" | "calldata" | "burnGas";
	let value: number | string;

	if (N_SSTORE > 0) {
		mode = "sstore";
		value = N_SSTORE;
	} else if (N_EVENTS > 0) {
		mode = "events";
		value = N_EVENTS;
	} else {
		mode = "calldata";
		value = "0x" + "ff".repeat(CALLDATA_SIZE);
	}

	if (BURN_GAS > 0) {
		mode = "burnGas";
		value = BURN_GAS;
	}

	return {
		shaperAddress,
		gasPrice,
		mode,
		value,
		multicall_address: maybeDeployMulticall3(vuClient),
	};
}

export default function ({
	shaperAddress,
	gasPrice,
	mode,
	value,
	multicall_address,
}: SetupData) {
	const contract = vuClient.newContract(shaperAddress, ARBITRARY_EXECUTION_ABI);

	// Determine the method name based on mode
	let methodName: string;
	switch (mode) {
		case "sstore":
			methodName = "runSstore";
			break;
		case "events":
			methodName = "runEvents";
			break;
		case "calldata":
			methodName = "runCalldata";
			break;
		case "burnGas":
			methodName = "runBurnGas";
			break;
		default:
			throw new Error(`Unknown mode: ${mode}`);
	}

	if (multicall_address) {
		// Batch CONFIG.batchSize calls together
		const calls = [];
		const encodedCalldata = contract.encodeABI(methodName, value);
		for (let i = 0; i < CONFIG.batchSize; i++) {
			calls.push({
				target: shaperAddress,
				allowFailure: false,
				calldata: encodedCalldata,
			});
		}
		vuClient.batchCallSync(multicall_address, calls, { gasPrice: gasPrice });
	} else {
		contract.txnSync(methodName, { gasPrice: gasPrice }, value);
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
