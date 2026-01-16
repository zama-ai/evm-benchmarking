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
		"../contracts/out/InputVerificationMock.sol/InputVerificationMock.abi.json",
	),
);
const CONTRACT_BIN = String(
	open("../contracts/out/InputVerificationMock.sol/InputVerificationMock.bin"),
);

// ======================= CONSTANTS =======================
const CIPHERTEXT_SIZE = 18795;

// ======================= TYPE DEFINITIONS =======================

interface SetupData {
	contract_address: string;
	accounts: Account[];
	gas_price: number;
	multicallAddress: string | null;
	ciphertextWithZKProof: string;
}

// ======================= ENV VARS =======================
const ACCOUNTS_FILE = (__ENV.ACCOUNTS_FILE as string) || null;
const CONTRACT_ADDRESS = (__ENV.CONTRACT_ADDRESS as string) || null;
const EXTRA_DATA = (__ENV.EXTRA_DATA as string) || "0x00";
const CONTRACT_CHAIN_ID =
	Number.parseInt(__ENV.CONTRACT_CHAIN_ID as string, 10) || 1;

// ======================= TEST OPTIONS =======================
export const options = getScenarios("input-verification");

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
		console.log("🔍 Deploying InputVerificationMock...");
		const receipt = masterClient.deployContract(CONTRACT_ABI, CONTRACT_BIN);

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

	// Generate ciphertext payload (18795 bytes of dummy data)
	const ciphertextWithZKProof = `0x${"aa".repeat(CIPHERTEXT_SIZE)}`;
	console.log(
		`📦 Ciphertext payload size: ${CIPHERTEXT_SIZE} bytes (${ciphertextWithZKProof.length} hex chars)`,
	);

	const gasPrice = masterClient.gasPrice();

	return {
		contract_address: contractAddress,
		accounts,
		gas_price: gasPrice,
		multicallAddress: maybeDeployMulticall3(masterClient) || null,
		ciphertextWithZKProof,
	};
}

// ======================= CALL DATA BUILDER =======================
function createCallData(
	contract: Contract,
	account: Account,
	ciphertextWithZKProof: string,
	_batchIndex: number = 0,
): Uint8Array {
	// verifyProofRequest(uint256 contractChainId, address contractAddress, address userAddress, bytes ciphertextWithZKProof, bytes extraData)
	return contract.encodeABI(
		"verifyProofRequest",
		CONTRACT_CHAIN_ID,
		account.address, // contractAddress (use account address as dummy)
		account.address, // userAddress
		ciphertextWithZKProof,
		EXTRA_DATA,
	);
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
					calldata: createCallData(
						vuContract,
						account,
						data.ciphertextWithZKProof,
						i,
					),
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
				input: createCallData(vuContract, account, data.ciphertextWithZKProof),
				gasPrice: data.gas_price,
				gas: 5_000_000,
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
	console.log(`\n🎯 === INPUT VERIFICATION BENCHMARK COMPLETE ===`);
	console.log(
		`🎯 Ciphertext size: ${CIPHERTEXT_SIZE} bytes, batch size: ${CONFIG.batchSize}`,
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
