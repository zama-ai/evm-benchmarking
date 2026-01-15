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
const NUM_CT_HANDLES = 1;

// Chain ID for contractsInfo (Sepolia testnet as example)
const CHAIN_ID = 11155111;

// Request validity duration in days
const DURATION_DAYS = 7;

// Note: publicKey (~800 bytes), signature (65 bytes), and extraData are now sent off-chain to KMS connectors
// Only the dataCommitment (32 bytes hash of this data) is stored on-chain, reducing payload from ~1.5KB to ~32 bytes

// ======================= TEST OPTIONS =======================

export const options = getScenarios("user-decrypt-flow");

// Single client using root account (deployer = aggregator)
const vuClient = initializeClient();

// ======================= TYPE DEFINITIONS =======================

interface SetupData {
	contractAddress: string;
	gasPrice: number;
	userAddress: string;
}

// ======================= SETUP =======================

export function setup(): SetupData {
	console.log("User Decryption Request Benchmark (Data Commitment Strategy)");
	console.log(`CT handles per request: ${NUM_CT_HANDLES}`);
	console.log(`Data commitment size: 32 bytes (replaces ~1.5KB payload)`);
	console.log(`Chain ID: ${CHAIN_ID}`);
	console.log(
		"Note: publicKey, signature, extraData sent off-chain to KMS connectors",
	);

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
	const walletInfo = vuClient.getWallet();

	return {
		contractAddress,
		gasPrice,
		userAddress: walletInfo.address,
	};
}

// ======================= HELPER FUNCTIONS =======================

/**
 * Generate mock CtHandleContractPair[] for the request
 * Each element is a tuple: [ctHandle (bytes32), contractAddress (address)]
 */
function generateCtHandleContractPairs(
	contractAddress: string,
): Array<[string, string]> {
	const pairs: Array<[string, string]> = [];
	for (let i = 0; i < NUM_CT_HANDLES; i++) {
		// Generate deterministic handles based on iteration index
		// Format matches real handle structure: [data | chain_id | fhe_type | version]
		const handleBase = BigInt(i + 1);
		const ctHandle = `0x${handleBase.toString(16).padStart(64, "0")}`;
		pairs.push([ctHandle, contractAddress]);
	}
	return pairs;
}

/**
 * Generate RequestValidity tuple: [startTimestamp, durationDays]
 */
function generateRequestValidity(): [number, number] {
	const startTimestamp = Math.floor(Date.now() / 1000);
	return [startTimestamp, DURATION_DAYS];
}

/**
 * Generate ContractsInfo tuple: [chainId, addresses[]]
 */
function generateContractsInfo(contractAddress: string): [number, string[]] {
	return [CHAIN_ID, [contractAddress]];
}

/**
 * Generate mock data commitment (hash of off-chain data)
 * In production, this would be: keccak256(abi.encode(publicKey, signature, extraData))
 * For benchmarking, we use a deterministic mock hash
 */
function generateDataCommitment(iterationIndex: number): string {
	// Generate unique commitment per iteration for realistic testing
	const commitmentBase = BigInt(0xdeadbeef + iterationIndex);
	return `0x${commitmentBase.toString(16).padStart(64, "0")}`;
}

// ======================= MAIN TEST FUNCTION =======================

export default function ({
	contractAddress,
	gasPrice,
	userAddress,
}: SetupData): void {
	const contract = vuClient.newContract(contractAddress, CONTRACT_ABI);

	// Send request transaction with data commitment (new optimized signature)
	// userDecryptionRequest(
	//   CtHandleContractPair[] ctHandleContractPairs,
	//   RequestValidity requestValidity,
	//   ContractsInfo contractsInfo,
	//   address userAddress,
	//   bytes32 dataCommitment  // <-- replaces publicKey, signature, extraData (saves ~1.5KB)
	// )
	const ctHandleContractPairs = generateCtHandleContractPairs(contractAddress);
	const requestValidity = generateRequestValidity();
	const contractsInfo = generateContractsInfo(contractAddress);

	// Use __ITER to get unique commitment per iteration (k6 built-in variable)
	// @ts-expect-error - __ITER is injected by k6 runtime
	const iterationIndex = typeof __ITER !== "undefined" ? __ITER : 0;
	const dataCommitment = generateDataCommitment(iterationIndex);

	const requestCallData = contract.encodeABI(
		"userDecryptionRequest",
		ctHandleContractPairs,
		requestValidity,
		contractsInfo,
		userAddress,
		dataCommitment,
	);

	const requestReceipt = vuClient.sendTransactionSync({
		to: contractAddress,
		input: requestCallData,
		gasPrice: gasPrice,
		gas: 5_000_000,
		value: 0,
	});
	if (requestReceipt.status !== 1) {
		fail(`Request transaction failed with status: ${requestReceipt.status}`);
	}
}

export function monitor() {
	monitoringLoop();
}

// ======================= SUMMARY HANDLER =======================

export function handleSummary(
	data: Record<string, unknown>,
): Record<string, string> {
	console.log("=== USER DECRYPTION REQUEST BENCHMARK SUMMARY ===");
	console.log("Data Commitment Strategy (Optimized Payload)");
	console.log("Each iteration = 1 request tx");
	console.log(`CT handles per request: ${NUM_CT_HANDLES}`);
	console.log(`Data commitment size: 32 bytes`);
	console.log(`Payload reduction: ~1.5KB → 32 bytes (~98% reduction)`);
	console.log(`Chain ID: ${CHAIN_ID}`);

	return {
		stdout: textSummary(data, { indent: " ", enableColors: true }),
		"summary.json": JSON.stringify(data),
	};
}
