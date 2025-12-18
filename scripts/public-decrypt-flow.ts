import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.2/index.js";
import { fail } from "k6";
import { initializeClient } from "../helpers/init.ts";
import { monitoringLoop } from "../helpers/monitoring.ts";
import { getScenarios } from "../helpers/scenarios.ts";

// ======================= CONTRACT ARTIFACTS =======================
const CONTRACT_ABI = String(
	open("../contracts/out/DecryptionMockV2.sol/DecryptionMockV2.abi.json"),
);
const CONTRACT_BIN = String(
	open("../contracts/out/DecryptionMockV2.sol/DecryptionMockV2.bin"),
);

// ======================= CONSTANTS =======================

// Number of ciphertext handles per request (mirrored from real tx)
const NUM_CT_HANDLES = 2;

// Size of decrypted payload in bytes (response data)
const PAYLOAD_SIZE_BYTES = 355;

// ======================= TEST OPTIONS =======================

export const options = getScenarios("public-decrypt-flow");

// Single client using root account (deployer = aggregator)
const vuClient = initializeClient();

// ======================= TYPE DEFINITIONS =======================

interface SetupData {
	contractAddress: string;
	gasPrice: number;
}

// ======================= SETUP =======================

export function setup(): SetupData {
	console.log("Public Decryption Flow Benchmark");
	console.log(`CT handles per request: ${NUM_CT_HANDLES}`);
	console.log(`Payload size: ${PAYLOAD_SIZE_BYTES} bytes`);

	// Deploy contract - deployer becomes the aggregator
	console.log("Deploying DecryptionMockV2 contract...");
	const receipt = vuClient.deployContract(CONTRACT_ABI, CONTRACT_BIN);
	if (receipt.status !== 1) {
		console.error(
			`Contract deployment failed - receipt: ${JSON.stringify(receipt)}`,
		);
		throw new Error("Contract deployment failed");
	}

	const contractAddress = String(receipt.contractAddress);
	console.log(`Contract deployed at: ${contractAddress}`);

	const gasPrice = vuClient.gasPrice();

	return {
		contractAddress,
		gasPrice,
	};
}

// ======================= HELPER FUNCTIONS =======================

/**
 * Generate mock ciphertext handles for the request
 */
function generateCtHandles(): string[] {
	const handles: string[] = [];
	for (let i = 0; i < NUM_CT_HANDLES; i++) {
		// Generate deterministic handles based on iteration index
		const handleBase = BigInt(i + 1);
		handles.push(`0x${handleBase.toString(16).padStart(64, "0")}`);
	}
	return handles;
}

// ======================= MAIN TEST FUNCTION =======================

export default function ({ contractAddress, gasPrice }: SetupData): void {
	const contract = vuClient.newContract(contractAddress, CONTRACT_ABI);

	// Step 1: Send request transaction
	const ctHandles = generateCtHandles();
	const requestCallData = contract.encodeABI(
		"publicDecryptionRequest",
		ctHandles,
		"0x00",
	);
	const requestReceipt = vuClient.sendTransactionSync({
		to: contractAddress,
		input: requestCallData,
		gasPrice: gasPrice,
		gas: 500_000,
		value: 0,
	});
	if (requestReceipt.status !== 1) {
		fail(`Request transaction failed with status: ${requestReceipt.status}`);
	}

	// Extract decryptionId from event logs
	const decryptionIdEmitted = requestReceipt.logs[0]?.topics[1];
	if (!decryptionIdEmitted) {
		fail("DecryptionId not found in event");
	}
	const decryptionId = BigInt(decryptionIdEmitted);

	// Step 2: Send response transaction (only aggregator can call this)
	const decryptedResult = `0x${"ff".repeat(PAYLOAD_SIZE_BYTES)}`;
	const responseCallData = contract.encodeABI(
		"publicDecryptionResponse",
		decryptionId,
		decryptedResult,
		"0x00",
	);
	const responseReceipt = vuClient.sendTransactionSync({
		to: contractAddress,
		input: responseCallData,
		gasPrice: gasPrice,
		gas: 500_000,
		value: 0,
	});
	if (responseReceipt.status !== 1) {
		fail(`Response transaction failed with status: ${responseReceipt.status}`);
	}
}

export function monitor() {
	monitoringLoop();
}

// ======================= SUMMARY HANDLER =======================

export function handleSummary(
	data: Record<string, unknown>,
): Record<string, string> {
	console.log("=== PUBLIC DECRYPTION FLOW BENCHMARK SUMMARY ===");
	console.log("Each iteration = 1 request tx + 1 response tx (2 tx total)");
	console.log(`CT handles per request: ${NUM_CT_HANDLES}`);
	console.log(`Payload size: ${PAYLOAD_SIZE_BYTES} bytes`);

	return {
		stdout: textSummary(data, { indent: " ", enableColors: true }),
		"summary.json": JSON.stringify(data),
	};
}
