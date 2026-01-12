import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.2/index.js";
import { fail } from "k6";
import exec from "k6/execution";
import { type Call3, Client, type Contract } from "k6/x/ethereum";
import type { Account } from "k6/x/ethereum/wallet";
import {
	fundTestAccounts,
	initializeClient,
	loadAccountsFromFile,
	maybeDeployMulticall3,
	refundTestAccounts,
} from "../helpers/init.ts";
import { monitoringLoop } from "../helpers/monitoring.ts";
import {
	CONFIG,
	getMaxIterationsPerVu,
	getScenarios,
} from "../helpers/scenarios.ts";

// ======================= CONTRACT ARTIFACTS =======================
const CONTRACT_ABI = String(
	open("../contracts/out/DecryptionMock.sol/DecryptionMock.abi.json"),
);
const CONTRACT_BIN = String(
	open("../contracts/out/DecryptionMock.sol/DecryptionMock.bin"),
);

// ======================= TYPE DEFINITIONS =======================

interface SetupData {
	contract_address: string;
	accounts: Account[];
	root_address: string;
	// if gas_price were to not be a fixed value, adapt it dynamically
	gas_price: number;
	multicallAddress: string | null;
}

const ACCOUNTS_FILE = (__ENV.ACCOUNTS_FILE as string) || null;
const CONTRACT_ADDRESS = (__ENV.CONTRACT_ADDRESS as string) || null;
const CONSENSUS_THRESHOLD =
	Number.parseInt(__ENV.CONSENSUS_THRESHOLD as string, 10) || 2;
const PAYLOAD_SIZE_BYTES =
	Number.parseInt((__ENV.PAYLOAD_SIZE_BYTES || "1300") as string, 10) || 1300;

// ======================= TEST OPTIONS =======================

export const options = getScenarios("user-decrypt");

let vuClient: Client | null = null;
let vuContract: Contract | null = null;

// ======================= SETUP =======================

export function setup(): SetupData {
	let accounts: Account[] | null = null;

	// Try to load accounts from file if specified
	if (ACCOUNTS_FILE) {
		console.log(`🔍 Loading accounts from: ${ACCOUNTS_FILE}`);
		accounts = loadAccountsFromFile(ACCOUNTS_FILE);
	}

	// If no accounts loaded from file, create new ones
	const masterClient = initializeClient();
	if (!accounts) {
		console.log(`💰 Creating ${CONFIG.maxVUs + 1} funded test accounts...`);
		// + 1 to account for the monitoring VU.
		const mnemonic = __ENV.MNEMONIC;
		if (!mnemonic) {
			throw new Error("MNEMONIC must be provided in env to fund accounts.");
		}
		accounts = fundTestAccounts(masterClient, CONFIG.maxVUs + 1, mnemonic);
	}

	// Validate we have enough accounts
	if (accounts.length < CONFIG.maxVUs) {
		throw new Error(
			`❌ Need ${CONFIG.maxVUs} accounts, but only have ${accounts.length}`,
		);
	}

	let contractAddress: string;
	// Deploy contract if not provided
	if (!CONTRACT_ADDRESS) {
		console.log(
			`🔍 Deploying contract with consensus threshold: ${CONSENSUS_THRESHOLD}`,
		);
		const receipt = masterClient.deployContract(
			CONTRACT_ABI,
			CONTRACT_BIN,
			CONSENSUS_THRESHOLD,
		);
		if (receipt.status !== 1) {
			console.error(
				`❌ Contract deployment failed - receipt: ${JSON.stringify(receipt)}`,
			);
			throw new Error("❌ Contract deployment failed");
		}

		contractAddress = String(receipt.contractAddress);
		console.log(`✅ Contract deployed at: ${contractAddress}`);
	} else {
		contractAddress = CONTRACT_ADDRESS;
		console.log(`🔍 Using existing contract: ${contractAddress}`);
	}

	const gasPrice = masterClient.gasPrice();
	const walletInfo = masterClient.getWallet();

	return {
		contract_address: contractAddress,
		accounts: accounts,
		root_address: walletInfo.address,
		gas_price: gasPrice,
		multicallAddress: maybeDeployMulticall3(masterClient) || null,
	};
}

// ======================= MAIN TEST FUNCTION =======================

/**
 * Creates call data for a userDecryptionResponse transaction
 */
function createDecryptionCallData(
	contract: Contract,
	batchIndex: number = 0,
): Uint8Array {
	// See Decryption.sol on the base decryption ID calculation
	// Note: this cannot be done in the `setup` phase as the auto-serialization of BigInt to JSON done by K6 loses the precision.
	const baseDecryptionId = (2n << 248n) + 1n;
	// Create unique decryptionOffset using VU ID, iteration, and batch index
	// Multipliers are calculated dynamically based on test parameters:
	// - getMaxIterationsPerVu(): scenario-aware max iterations per VU
	// - CONFIG.batchSize: number of calls per batch
	// Formula: VU_ID * (max_iterations * batchSize) + iteration * batchSize + batchIndex
	const maxIterationsPerVu = BigInt(getMaxIterationsPerVu());
	const iterationMultiplier =
		BigInt(maxIterationsPerVu) * BigInt(CONFIG.batchSize);
	const batchMultiplier = BigInt(CONFIG.batchSize);

	const decryptionOffset =
		BigInt(exec.vu.idInTest - 1) * iterationMultiplier +
		BigInt(exec.vu.iterationInScenario) * batchMultiplier +
		BigInt(batchIndex);

	// Note: baseDecryptionId is _supposed_ to be a bigint but for some reason there's a type error if we don't cast it to BigInt
	const decryptionId = BigInt(baseDecryptionId) + decryptionOffset;
	const randomBytes = Math.floor(Math.random() * 0xffffffff)
		.toString(16)
		.padStart(8, "0");
	const signature = `0x${randomBytes.repeat(16)}01`;

	return contract.encodeABI(
		"userDecryptionResponse",
		decryptionId,
		`0x${"ff".repeat(PAYLOAD_SIZE_BYTES)}`, // userDecryptedShare
		signature, // signature (65 bytes)
		"0x00", // extraData
	);
}

export default function (data: SetupData): void {
	const vuIndex = exec.vu.idInTest - 1;
	const accountIndex = vuIndex;

	// Validate account availability
	if (accountIndex >= data.accounts.length) {
		console.log(
			`❌ VU ${exec.vu.idInTest}: No account available (index ${accountIndex})`,
		);
		return;
	}

	const account = data.accounts[accountIndex];

	if (!account) {
		throw new Error("Account not found for current VU");
	}

	const rpcUrl = __ENV.ETH_RPC_URL;
	if (!rpcUrl) {
		throw new Error("ETH_RPC_URL environment variable is not set");
	}

	if (!vuClient || !vuContract) {
		vuClient = new Client({
			url: rpcUrl,
			privateKey: account.privateKey,
		});
		vuContract = vuClient.newContract(data.contract_address, CONTRACT_ABI);
	}

	try {
		if (data.multicallAddress) {
			// Build batch of userDecryptionResponse calls
			const calls: Call3[] = [];
			for (let i = 0; i < CONFIG.batchSize; i++) {
				const callData = createDecryptionCallData(vuContract, i);

				calls.push({
					target: data.contract_address,
					allowFailure: false,
					calldata: callData,
				});
			}

			// Send batch via Multicall3
			const receipt = vuClient.batchCallSync(data.multicallAddress, calls, {
				gasPrice: data.gas_price,
			});
			if (receipt.status !== 1) {
				fail(
					`❌ VU ${exec.vu.idInTest}: Batch transaction failed with status: ${receipt.status}`,
				);
			}
		} else {
			// Single transaction mode
			const callData = createDecryptionCallData(vuContract);
			const receipt = vuClient.sendTransactionSync({
				to: data.contract_address,
				input: callData,
				gasPrice: data.gas_price,
				gas: 3_100_000,
				value: 0,
			});
			if (receipt.status !== 1) {
				fail(
					`❌ VU ${exec.vu.idInTest}: Transaction failed with status: ${receipt.status}`,
				);
			}
		}
	} catch (error) {
		console.error(`❌ VU ${exec.vu.idInTest}: ${error}`);
	}
}

export function monitor() {
	monitoringLoop();
}

// ======================= TEARDOWN =======================

export async function teardown(data: SetupData): Promise<void> {
	console.log("\n🔄 Starting ETH refund process...");
	const masterClient = initializeClient();
	const totalRefunded = await refundTestAccounts(
		masterClient,
		data.root_address,
		data.accounts,
	);
	console.log(
		`✅ Refund complete: ${(totalRefunded / 1e18).toFixed(6)} ETH returned to root account`,
	);

	console.log(`🎯 === CONCURRENT TEST SUMMARY ===`);
	console.log(
		`🎯 All ${CONSENSUS_THRESHOLD} VUs completed their transactions concurrently`,
	);
	console.log(
		`🎯 Each transaction confirmation measured independently and in parallel`,
	);
}

// ======================= SUMMARY HANDLER =======================

export function handleSummary(
	data: Record<string, unknown>,
): Record<string, string> {
	return {
		stdout: textSummary(data, { indent: " ", enableColors: true }),
		"summary.json": JSON.stringify(data),
	};
}
