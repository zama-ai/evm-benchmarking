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
} from "../helpers/init.ts";
import { monitoringLoop } from "../helpers/monitoring.ts";
import { CONFIG, getScenarios } from "../helpers/scenarios.ts";

// ======================= CONTRACT ARTIFACTS =======================
const CONTRACT_ABI = String(
	open(
		"../contracts/out/AllowPublicDecryptMock.sol/AllowPublicDecryptMock.abi.json",
	),
);
const CONTRACT_BIN = String(
	open(
		"../contracts/out/AllowPublicDecryptMock.sol/AllowPublicDecryptMock.bin",
	),
);

// ======================= METRICS =======================

// ======================= TYPE DEFINITIONS =======================

interface SetupData {
	contract_address: string;
	accounts: Account[];
	gas_price: number;
	multicallAddress: string | null;
}

// ======================= ENV VARS =======================
const ACCOUNTS_FILE = (__ENV.ACCOUNTS_FILE as string) || null;
const CONTRACT_ADDRESS = (__ENV.CONTRACT_ADDRESS as string) || null;
const CONSENSUS_THRESHOLD =
	Number.parseInt(__ENV.CONSENSUS_THRESHOLD as string, 10) || 2;
const EXTRA_DATA = (__ENV.EXTRA_DATA as string) || "0x00";

// ======================= TEST OPTIONS =======================
export const options = getScenarios("allow-public-decrypt");

let vuClient: Client | null = null;
let vuContract: Contract | null = null;

// ======================= SETUP =======================
export function setup(): SetupData {
	let accounts: Account[] | null = null;

	if (ACCOUNTS_FILE) {
		console.log(`🔍 Loading accounts from: ${ACCOUNTS_FILE}`);
		accounts = loadAccountsFromFile(ACCOUNTS_FILE);
	}

	const masterClient = initializeClient();
	if (!accounts) {
		console.log(
			`💰 Creating ${CONFIG.maxVUs + 1} funded test accounts (includes monitor VU)...`,
		);
		const mnemonic = __ENV.MNEMONIC;
		if (!mnemonic) {
			throw new Error("MNEMONIC must be provided in env to fund accounts.");
		}
		accounts = fundTestAccounts(masterClient, CONFIG.maxVUs + 1, mnemonic);
	}

	if (accounts.length !== CONFIG.maxVUs + 1) {
		throw new Error(
			`❌ Need ${CONFIG.maxVUs} accounts, but only have ${accounts.length}`,
		);
	}

	let contractAddress: string;
	if (!CONTRACT_ADDRESS) {
		console.log(
			`🔍 Deploying AllowPublicDecryptMock with consensus threshold: ${CONSENSUS_THRESHOLD}`,
		);
		const receipt = masterClient.deployContract(
			CONTRACT_ABI,
			CONTRACT_BIN,
			CONSENSUS_THRESHOLD,
		);

		if (receipt.status !== 1) {
			throw new Error(
				`❌ Contract deployment failed - receipt: ${JSON.stringify(receipt)}`,
			);
		}

		contractAddress = String(receipt.contractAddress);
		console.log(`✅ Contract deployed at: ${contractAddress}`);
	} else {
		contractAddress = CONTRACT_ADDRESS;
		console.log(`🔍 Using existing contract: ${contractAddress}`);
	}

	const contract = masterClient.newContract(contractAddress, CONTRACT_ABI);

	// Allow all handles to pass simulated registration checks (single tx)
	const gasPrice = masterClient.gasPrice();
	const tx = contract.txnSync(
		"setAllHandlesRegistered",
		{ gasPrice: gasPrice },
		true,
	);
	console.log(
		`✅ Enabled handle registration wildcard (tx: ${tx.transactionHash})`,
	);

	return {
		contract_address: contractAddress,
		accounts,
		gas_price: gasPrice,
		multicallAddress: maybeDeployMulticall3(masterClient) || null,
	};
}

// ======================= CALL DATA BUILDER =======================
function createCallData(
	contract: Contract,
	batchIndex: number = 0,
): Uint8Array {
	// Unique handle per tx: combine VU id, iteration, batch index
	const durationSeconds = CONFIG.duration;
	const maxIterations = BigInt(CONFIG.rate * durationSeconds);
	const batchSize = BigInt(CONFIG.batchSize);

	const handleOffset =
		(BigInt(exec.vu.idInTest - 1) * maxIterations +
			BigInt(exec.vu.iterationInScenario)) *
			batchSize +
		BigInt(batchIndex);

	// Construct deterministic bytes32
	const ctHandle = `0x${handleOffset.toString(16).padStart(64, "0")}`;
	return contract.encodeABI("allowPublicDecrypt", ctHandle, EXTRA_DATA);
}

// ======================= MAIN TEST FUNCTION =======================
export default function (data: SetupData): void {
	const vuIndex = exec.vu.idInTest - 1;
	const account = data.accounts[vuIndex];

	if (!account) {
		fail(`❌ VU ${exec.vu.idInTest}: No account available`);
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
		if (data.multicallAddress && CONFIG.batchSize > 1) {
			const calls: Call3[] = [];
			for (let i = 0; i < CONFIG.batchSize; i++) {
				calls.push({
					target: data.contract_address,
					allowFailure: false,
					calldata: createCallData(vuContract, i),
				});
			}

			const receipt = vuClient.batchCallSync(data.multicallAddress, calls, {
				gasPrice: data.gas_price,
			});

			if (receipt.status !== 1) {
				fail(
					`❌ VU ${exec.vu.idInTest}: Batch failed with status ${receipt.status}`,
				);
			}
		} else {
			const receipt = vuClient.sendTransactionSync({
				to: data.contract_address,
				input: createCallData(vuContract),
				gasPrice: data.gas_price,
				gas: 1_000_000,
				value: 0,
			});

			if (receipt.status !== 1) {
				fail(
					`❌ VU ${exec.vu.idInTest}: Tx failed with status ${receipt.status}`,
				);
			}
		}
	} catch (error) {
		console.error(`❌ VU ${exec.vu.idInTest}: ${error}`);
	}
}

// ======================= MONITORING =======================
export function monitor() {
	monitoringLoop();
}

// ======================= TEARDOWN =======================
export function teardown(_data: SetupData): void {
	console.log(`\n🎯 === ALLOW PUBLIC DECRYPT BENCHMARK COMPLETE ===`);
	console.log(
		`🎯 Consensus threshold: ${CONSENSUS_THRESHOLD}, batch size: ${CONFIG.batchSize}`,
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
