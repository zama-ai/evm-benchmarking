import exec from "k6/execution";
import eth, { type Call3Value, type Client, type Options } from "k6/x/ethereum";
import wallet, { type Account } from "k6/x/ethereum/wallet";

const MULTICALL3_ABI = open(
	"../contracts/out/Multicall3.sol/Multicall3.abi.json",
);
const MULTICALL3_BIN = open("../contracts/out/Multicall3.sol/Multicall3.bin");
const ETHER_FUNDING_AMOUNT = Number(__ENV.ETHER_FUNDING_AMOUNT) || 0.001;

export function initializeClient() {
	if (!__ENV.ETH_RPC_URL) {
		throw new Error("ETH_RPC_URL must be provided in env.");
	}
	const rootAccount = resolveRootAccount();
	const clientOpts: Options = {
		url: __ENV.ETH_RPC_URL,
		privateKey: rootAccount.privateKey,
	};
	return new eth.Client(clientOpts);
}

/**
 * Resolve the root account from the environment variables. Prioritizes PRIVATE_KEY over MNEMONIC.
 * @returns - Object containing the root account address and private key
 */
export function resolveRootAccount() {
	if (__ENV.PRIVATE_KEY) {
		const pk = String(__ENV.PRIVATE_KEY).replace(/^0x/, "");
		const acct = wallet.accountFromPrivateKey(pk);
		return { address: acct.address, privateKey: acct.privateKey };
	}
	if (__ENV.MNEMONIC) {
		const acct = wallet.accountsFromMnemonic(__ENV.MNEMONIC, 1)[0];
		if (!acct) {
			throw new Error("Failed to derive account from MNEMONIC");
		}
		return { address: acct.address, privateKey: acct.privateKey };
	}
	throw new Error("PRIVATE_KEY or MNEMONIC must be provided in env.");
}

/// Deploys the multicall3 contract if BATCH_SIZE is greater than 1.
/// @param client - Client instance
/// @returns The address of the deployed multicall3 contract or null if BATCH_SIZE is 1.
export function maybeDeployMulticall3(client: Client) {
	const BATCH_SIZE = Number(__ENV.BATCH_SIZE) || 1;
	if (BATCH_SIZE > 1) {
		const receipt = client.deployContract(MULTICALL3_ABI, MULTICALL3_BIN);
		return String(receipt.contractAddress);
	}
	return null;
}

/**
 * Accounts file data structure
 */
interface AccountsData {
	timestamp: string;
	root_address: string;
	funded_accounts_count: number;
	accounts: Account[];
}

/**
 * Load accounts from a JSON file
 * @param filename - Path to the accounts JSON file
 * @returns Array of accounts or null if loading fails
 */
export function loadAccountsFromFile(filename: string): Account[] | null {
	try {
		// Use k6's built-in open() function to read files at init time
		const fileContent = open(filename);
		if (
			!fileContent ||
			typeof fileContent !== "string" ||
			(fileContent as string).trim() === ""
		) {
			throw new Error(`File content is empty or invalid: ${filename}`);
		}
		const accountsData = JSON.parse(fileContent) as AccountsData;
		console.log(
			`✅ Loaded ${accountsData.funded_accounts_count} accounts from: ${filename}`,
		);

		return accountsData.accounts;
	} catch (error) {
		console.error(`❌ Failed to load accounts from file: ${error}`);
		return null;
	}
}

/**
 * Fund test accounts with ETH from a root account using Multicall3 for batching
 * @param root_address - Address of the root account with funds
 * @param client - Client instance
 * @param accountCount - Number of accounts to fund (defaults to VU count)
 * @param mnemonic - Optional mnemonic for deterministic account generation
 * @returns Array of funded accounts
 */
export function fundTestAccounts(
	client: Client,
	accountCount: number | null = null,
	mnemonic: string,
): Account[] {
	const accounts: Account[] = [];
	const walletInfo = client.getWallet();
	console.log(`🔍 Root address: ${walletInfo.address}`);

	// Use provided account count or default to VU count
	const numAccountsToFund = accountCount || exec.instance.vusInitialized;
	console.log(`💰 Funding ${numAccountsToFund} test accounts...`);

	// Deploy Multicall3 contract for batching
	console.log(`📦 Deploying Multicall3 contract...`);
	const receipt = client.deployContract(MULTICALL3_ABI, MULTICALL3_BIN);
	const multicallAddress = String(receipt.contractAddress);
	console.log(`✅ Multicall3 deployed at: ${multicallAddress}`);

	// Use deterministic generation from a set mnemonic.
	const derivedAccounts = wallet.accountsFromMnemonic(
		mnemonic,
		numAccountsToFund,
	);
	for (let i = 0; i < numAccountsToFund; i++) {
		const account = derivedAccounts[i];
		if (!account) {
			throw new Error(`Failed to derive account at index ${i} from mnemonic`);
		}
		accounts[i] = {
			privateKey: account.privateKey,
			address: account.address,
		};
	}
	console.log(
		`🔑 Generated ${numAccountsToFund} deterministic accounts from mnemonic`,
	);

	// Fund accounts in batches using Multicall3
	const BATCH_SIZE = 100;
	const gasPrice = client.gasPrice();

	console.log(
		`⏳ Sending ${numAccountsToFund} funding transactions in batches of ${BATCH_SIZE}...`,
	);

	let totalFunded = 0;
	for (
		let batchStart = 0;
		batchStart < numAccountsToFund;
		batchStart += BATCH_SIZE
	) {
		const batchEnd = Math.min(batchStart + BATCH_SIZE, numAccountsToFund);
		const calls: Call3Value[] = [];

		for (let i = batchStart; i < batchEnd; i++) {
			const account = accounts[i];
			if (!account) {
				throw new Error(`Account at index ${i} is undefined`);
			}
			calls.push({
				target: account.address,
				allowFailure: false,
				value: Number(ETHER_FUNDING_AMOUNT * 1e18),
				calldata: new Uint8Array(0), // Empty calldata for ETH transfer
			});
		}

		const _batchReceipt = client.batchCallValueSync(multicallAddress, calls, {
			gasPrice: gasPrice,
		});
		if (_batchReceipt.status !== 1) {
			throw new Error(
				`Batch transaction failed with status: ${_batchReceipt.status}`,
			);
		}

		totalFunded += calls.length;
		const progress = Math.round((totalFunded / numAccountsToFund) * 100);
		const barLength = 30;
		const filledLength = Math.round(
			(barLength * totalFunded) / numAccountsToFund,
		);
		const bar = "█".repeat(filledLength) + "░".repeat(barLength - filledLength);
		client.print(
			`\r💸 Funding accounts: [${bar}] ${progress}% (${totalFunded}/${numAccountsToFund})`,
		);
	}

	// Print newline after progress bar completes
	console.log("\n✅ All accounts funded successfully");

	console.log(
		`ℹ️ Account data created (file writing not supported during k6 execution):`,
	);
	console.log(`   Accounts: ${accounts.length}`);
	console.log(`   Root: ${walletInfo.address}`);
	console.log(`   Use --summary-export to save test results with account info`);

	return accounts;
}

interface PendingRefund {
	txHash: string;
	amount: number;
	accountIndex: number;
}

/**
 * Refund ETH from test accounts back to the root account
 * Sends transactions in parallel batches for better performance.
 * @param client - Client instance (used for gas price and receipt polling)
 * @param rootAddress - Address of the root account to receive refunds
 * @param accounts - Array of accounts to refund from
 * @returns Total amount of ETH refunded (in wei)
 */
export async function refundTestAccounts(
	client: Client,
	rootAddress: string,
	accounts: Account[],
): Promise<number> {
	console.log(`\n💰 Refunding ETH from ${accounts.length} test accounts...`);

	const gasPrice = client.gasPrice();
	const estimatedGasCost = gasPrice * 21000; // Standard ETH transfer gas
	const minBalanceForRefund = estimatedGasCost * 1.1; // Add 10% buffer

	let totalRefunded = 0;
	let refundedCount = 0;
	let skippedCount = 0;

	if (!__ENV.ETH_RPC_URL) {
		throw new Error("ETH_RPC_URL must be provided in env.");
	}

	const BATCH_SIZE = 50;
	const ARBITRUM_L1_GAS_FEE = 500;
	const INTRINSIC_GAS = 21000;
	const gasLimit = INTRINSIC_GAS + ARBITRUM_L1_GAS_FEE;

	// Process refunds in parallel batches
	for (
		let batchStart = 0;
		batchStart < accounts.length;
		batchStart += BATCH_SIZE
	) {
		const batchEnd = Math.min(batchStart + BATCH_SIZE, accounts.length);
		const pendingRefunds: PendingRefund[] = [];

		// Phase 1: Send all transactions in the batch (non-blocking)
		for (let i = batchStart; i < batchEnd; i++) {
			const account = accounts[i];
			if (!account) {
				console.log(`⚠️  Skipping undefined account at index ${i}`);
				skippedCount++;
				continue;
			}

			// Query account balance
			const balance = client.getBalance(account.address, null);

			// Skip if balance is too low to cover gas
			if (balance < minBalanceForRefund) {
				skippedCount++;
				continue;
			}

			// Calculate refund amount (leave gas for the transfer)
			const refundAmount = balance - minBalanceForRefund;

			try {
				// Create a client with this account's private key
				const accountClient = new eth.Client({
					url: __ENV.ETH_RPC_URL,
					privateKey: account.privateKey,
				});

				// Send transaction without waiting for receipt
				const txHash = accountClient.sendRawTransaction({
					to: rootAddress,
					value: Number(refundAmount),
					gasPrice: gasPrice,
					gas: gasLimit,
				});

				pendingRefunds.push({
					txHash,
					amount: refundAmount,
					accountIndex: i,
				});
			} catch (error) {
				console.log(
					`\n❌ Error sending refund from account ${i + 1}/${accounts.length}: ${error}`,
				);
				skippedCount++;
			}
		}

		// Phase 2: Wait for all receipts in this batch concurrently
		if (pendingRefunds.length > 0) {
			const receiptPromises = pendingRefunds.map((pending) =>
				client
					.waitForTransactionReceipt(pending.txHash)
					.then((receipt) => ({ receipt, pending, error: null }))
					.catch((error: Error) => ({ receipt: null, pending, error })),
			);

			const results = await Promise.all(receiptPromises);

			// Process results
			for (const result of results) {
				if (result.error) {
					console.log(
						`\n❌ Error waiting for receipt (account ${result.pending.accountIndex + 1}): ${result.error}`,
					);
					skippedCount++;
				} else if (result.receipt && result.receipt.status === 1) {
					totalRefunded += result.pending.amount;
					refundedCount++;
				} else {
					console.log(
						`\n❌ Refund failed for account ${result.pending.accountIndex + 1}: Transaction status ${result.receipt?.status}`,
					);
					skippedCount++;
				}
			}
		}

		// Progress logging after each batch
		const progress = Math.round((batchEnd / accounts.length) * 100);
		console.log(`Progress: ${progress}% (${batchEnd}/${accounts.length})`);
		const barLength = 30;
		const filledLength = Math.round((barLength * batchEnd) / accounts.length);
		const bar = "█".repeat(filledLength) + "░".repeat(barLength - filledLength);
		client.print(
			`\r💸 Refunding accounts: [${bar}] ${progress}% (${batchEnd}/${accounts.length})`,
		);
	}

	console.log("");
	console.log(
		`✅ Refund complete: ${refundedCount} accounts refunded, ${skippedCount} skipped`,
	);
	console.log(
		`💰 Total ETH recovered: ${(totalRefunded / 1e18).toFixed(6)} ETH`,
	);

	return totalRefunded;
}
