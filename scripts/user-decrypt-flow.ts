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

// Size of user's public key in bytes (real tx has ~800 bytes)
const PUBLIC_KEY_SIZE_BYTES = 800;

// Size of EIP712 signature (65 bytes: r=32, s=32, v=1)
const SIGNATURE_SIZE_BYTES = 65;

// Number of KMS nodes (shares in user decryption response)
const NUM_KMS_NODES = 13;

// Size of each decrypted share in bytes
const SHARE_SIZE_BYTES = 1300;

// Chain ID for contractsInfo (Sepolia testnet as example)
const CHAIN_ID = 11155111;

// Request validity duration in days
const DURATION_DAYS = 7;

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
	console.log("User Decryption Flow Benchmark (V2 - Real Signature)");
	console.log(`CT handles per request: ${NUM_CT_HANDLES}`);
	console.log(`Public key size: ${PUBLIC_KEY_SIZE_BYTES} bytes`);
	console.log(`Signature size: ${SIGNATURE_SIZE_BYTES} bytes`);
	console.log(`KMS nodes (shares per response): ${NUM_KMS_NODES}`);
	console.log(`Share size: ${SHARE_SIZE_BYTES} bytes`);
	console.log(`Chain ID: ${CHAIN_ID}`);

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
 * Generate mock user public key (realistic size from real transactions)
 */
function generatePublicKey(): string {
	return `0x${"aa".repeat(PUBLIC_KEY_SIZE_BYTES)}`;
}

/**
 * Generate mock EIP712 signature (65 bytes: r + s + v)
 */
function generateSignature(): string {
	return `0x${"bb".repeat(SIGNATURE_SIZE_BYTES)}`;
}

/**
 * Generate array of decrypted shares from all KMS nodes
 */
function generateUserDecryptedShares(): string[] {
	const shares: string[] = [];
	for (let i = 0; i < NUM_KMS_NODES; i++) {
		// Each share is SHARE_SIZE_BYTES, slightly different to simulate real shares
		const shareBase = (i + 1).toString(16).padStart(2, "0");
		shares.push(`0x${shareBase}${"ff".repeat(SHARE_SIZE_BYTES - 1)}`);
	}
	return shares;
}

// ======================= MAIN TEST FUNCTION =======================

export default function ({
	contractAddress,
	gasPrice,
	userAddress,
}: SetupData): void {
	const contract = vuClient.newContract(contractAddress, CONTRACT_ABI);

	// Step 1: Send request transaction with full signature matching real Decryption.sol
	// userDecryptionRequest(
	//   CtHandleContractPair[] ctHandleContractPairs,
	//   RequestValidity requestValidity,
	//   ContractsInfo contractsInfo,
	//   address userAddress,
	//   bytes publicKey,
	//   bytes signature,
	//   bytes extraData
	// )
	const ctHandleContractPairs = generateCtHandleContractPairs(contractAddress);
	const requestValidity = generateRequestValidity();
	const contractsInfo = generateContractsInfo(contractAddress);
	const publicKey = generatePublicKey();
	const signature = generateSignature();

	const requestCallData = contract.encodeABI(
		"userDecryptionRequest",
		ctHandleContractPairs,
		requestValidity,
		contractsInfo,
		userAddress,
		publicKey,
		signature,
		"0x00", // extraData
	);

	const requestReceipt = vuClient.sendTransactionSync({
		to: contractAddress,
		input: requestCallData,
		gasPrice: gasPrice,
		gas: 1_000_000,
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
	// GatewayV2 style: single aggregated response with all shares
	const userDecryptedShares = generateUserDecryptedShares();
	const responseCallData = contract.encodeABI(
		"userDecryptionResponse",
		decryptionId,
		userDecryptedShares,
		"0x00", // extraData
	);
	const responseReceipt = vuClient.sendTransactionSync({
		to: contractAddress,
		input: responseCallData,
		gasPrice: gasPrice,
		gas: 1_000_000,
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
	console.log("=== USER DECRYPTION FLOW BENCHMARK SUMMARY (V2) ===");
	console.log("Each iteration = 1 request tx + 1 response tx (2 tx total)");
	console.log(`CT handles per request: ${NUM_CT_HANDLES}`);
	console.log(`Public key size: ${PUBLIC_KEY_SIZE_BYTES} bytes`);
	console.log(`Signature size: ${SIGNATURE_SIZE_BYTES} bytes`);
	console.log(`KMS nodes (shares per response): ${NUM_KMS_NODES}`);
	console.log(`Share size: ${SHARE_SIZE_BYTES} bytes`);
	console.log(`Chain ID: ${CHAIN_ID}`);

	return {
		stdout: textSummary(data, { indent: " ", enableColors: true }),
		"summary.json": JSON.stringify(data),
	};
}
