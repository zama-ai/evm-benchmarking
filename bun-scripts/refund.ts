import {
	type Account,
	type Address,
	type Chain,
	createPublicClient,
	createWalletClient,
	defineChain,
	formatEther,
	http,
	type PublicClient,
	type Transport,
	type WalletClient,
} from "viem";
import { mnemonicToAccount, privateKeyToAccount } from "viem/accounts";

// Configuration from environment
const ETH_RPC_URL = process.env.ETH_RPC_URL || "http://127.0.0.1:8545";
const MNEMONIC = process.env.MNEMONIC;
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const N_ACCOUNTS = Number(process.env.N_ACCOUNTS) || 50;
const BATCH_SIZE = 100;

// Gas constants
const INTRINSIC_GAS = 21000n;
const ARBITRUM_L1_GAS_FEE = 1000n;
const GAS_LIMIT = INTRINSIC_GAS + ARBITRUM_L1_GAS_FEE;

interface RefundResult {
	address: Address;
	amount: bigint;
	txHash: string;
	success: boolean;
	error?: string;
}

function resolveRootAccount(): Account {
	if (PRIVATE_KEY) {
		const pk = PRIVATE_KEY.startsWith("0x")
			? (PRIVATE_KEY as `0x${string}`)
			: (`0x${PRIVATE_KEY}` as `0x${string}`);
		return privateKeyToAccount(pk);
	}
	if (MNEMONIC) {
		return mnemonicToAccount(MNEMONIC, { addressIndex: 0 });
	}
	throw new Error("PRIVATE_KEY or MNEMONIC must be provided in env.");
}

function deriveAccounts(mnemonic: string, count: number): Account[] {
	const accounts: Account[] = [];
	for (let i = 0; i < count; i++) {
		accounts.push(mnemonicToAccount(mnemonic, { addressIndex: i }));
	}
	return accounts;
}

async function getBalancesBatched(
	publicClient: PublicClient,
	addresses: Address[],
): Promise<Map<Address, bigint>> {
	const balancePromises = addresses.map((addr) =>
		publicClient.getBalance({ address: addr }),
	);
	const balances = await Promise.all(balancePromises);

	const balanceMap = new Map<Address, bigint>();
	for (let i = 0; i < addresses.length; i++) {
		balanceMap.set(addresses[i], balances[i]);
	}
	return balanceMap;
}

async function sendRefundTransaction(
	walletClient: WalletClient<Transport, Chain, Account>,
	publicClient: PublicClient,
	toAddress: Address,
	amount: bigint,
	gasPrice: bigint,
): Promise<RefundResult> {
	const fromAddress = walletClient.account.address;

	try {
		const txHash = await walletClient.sendTransaction({
			to: toAddress,
			value: amount,
			gas: GAS_LIMIT,
			gasPrice,
		});

		// Wait for receipt
		const receipt = await publicClient.waitForTransactionReceipt({
			hash: txHash,
		});

		return {
			address: fromAddress,
			amount,
			txHash,
			success: receipt.status === "success",
			error: receipt.status !== "success" ? "Transaction reverted" : undefined,
		};
	} catch (error) {
		return {
			address: fromAddress,
			amount,
			txHash: "",
			success: false,
			error: error instanceof Error ? error.message : String(error),
		};
	}
}

async function refundAccounts(
	publicClient: PublicClient,
	rootAddress: Address,
	accounts: Account[],
	gasPrice: bigint,
	chain: Chain,
): Promise<{ totalRefunded: bigint; successCount: number; skipCount: number }> {
	const minBalanceForRefund = (gasPrice * GAS_LIMIT * 11n) / 10n; // 10% buffer

	let totalRefunded = 0n;
	let successCount = 0;
	let skipCount = 0;

	// Process in batches
	for (
		let batchStart = 0;
		batchStart < accounts.length;
		batchStart += BATCH_SIZE
	) {
		const batchEnd = Math.min(batchStart + BATCH_SIZE, accounts.length);
		const batch = accounts.slice(batchStart, batchEnd);

		// Phase 1: Get all balances in parallel
		const addresses = batch.map((acc) => acc.address);
		const balances = await getBalancesBatched(publicClient, addresses);

		// Phase 2: Filter accounts with sufficient balance and prepare transactions
		const refundPromises: Promise<RefundResult>[] = [];

		for (const account of batch) {
			const balance = balances.get(account.address) || 0n;

			if (balance < minBalanceForRefund) {
				skipCount++;
				continue;
			}

			// Skip root account
			if (account.address.toLowerCase() === rootAddress.toLowerCase()) {
				skipCount++;
				continue;
			}

			const refundAmount = balance - minBalanceForRefund;

			// Create wallet client for this account
			const walletClient = createWalletClient({
				account,
				chain,
				transport: http(ETH_RPC_URL),
			});

			refundPromises.push(
				sendRefundTransaction(
					walletClient,
					publicClient,
					rootAddress,
					refundAmount,
					gasPrice,
				),
			);
		}

		// Phase 3: Wait for all transactions in this batch
		if (refundPromises.length > 0) {
			const results = await Promise.all(refundPromises);

			for (const result of results) {
				if (result.success) {
					totalRefunded += result.amount;
					successCount++;
				} else {
					console.error(
						`Failed refund from ${result.address}: ${result.error}`,
					);
					skipCount++;
				}
			}
		}

		// Progress logging
		const progress = Math.round((batchEnd / accounts.length) * 100);
		const barLength = 30;
		const filledLength = Math.round((barLength * batchEnd) / accounts.length);
		const bar =
			"\u2588".repeat(filledLength) + "\u2591".repeat(barLength - filledLength);
		console.log(
			`\rRefunding accounts: [${bar}] ${progress}% (${batchEnd}/${accounts.length})`,
		);
	}

	console.log(""); // Newline after progress bar
	return { totalRefunded, successCount, skipCount };
}

async function main() {
	if (!MNEMONIC) {
		throw new Error("MNEMONIC env var is required to derive accounts");
	}

	console.log("Refund Script - Using viem with parallel execution");
	console.log("=".repeat(50));
	console.log(`RPC URL: ${ETH_RPC_URL}`);
	console.log(`Batch size: ${BATCH_SIZE}`);
	console.log("");

	// Fetch chain ID from RPC
	const tempClient = createPublicClient({
		transport: http(ETH_RPC_URL),
	});
	const chainId = await tempClient.getChainId();
	console.log(`Chain ID: ${chainId}`);

	// Define custom chain with fetched chain ID
	const chain = defineChain({
		id: chainId,
		name: "Target Chain",
		nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
		rpcUrls: {
			default: { http: [ETH_RPC_URL] },
		},
	});

	// Setup clients with correct chain
	const publicClient = createPublicClient({
		chain,
		transport: http(ETH_RPC_URL),
	});

	const rootAccount = resolveRootAccount();
	console.log(`Root account: ${rootAccount.address}`);

	// Check root balance
	const rootBalance = await publicClient.getBalance({
		address: rootAccount.address,
	});
	console.log(`Root balance: ${formatEther(rootBalance)} ETH`);

	// Derive accounts
	console.log(`\nDeriving ${N_ACCOUNTS} accounts from mnemonic...`);
	const accountsToRefund = deriveAccounts(MNEMONIC, N_ACCOUNTS);
	console.log(`Accounts to process: ${accountsToRefund.length}`);

	// Get gas price
	const gasPrice = await publicClient.getGasPrice();
	console.log(`Gas price: ${gasPrice} wei`);

	// Execute refunds
	console.log("\nStarting refunds...");
	const startTime = Date.now();

	const { totalRefunded, successCount, skipCount } = await refundAccounts(
		publicClient,
		rootAccount.address,
		accountsToRefund,
		gasPrice,
		chain,
	);

	const elapsed = (Date.now() - startTime) / 1000;

	// Summary
	console.log("\n" + "=".repeat(50));
	console.log("Refund Summary");
	console.log("=".repeat(50));
	console.log(`Accounts processed: ${accountsToRefund.length}`);
	console.log(`Successful refunds: ${successCount}`);
	console.log(`Skipped: ${skipCount}`);
	console.log(`Total ETH recovered: ${formatEther(totalRefunded)} ETH`);
	console.log(`Time elapsed: ${elapsed.toFixed(2)}s`);
	console.log(
		`Throughput: ${(successCount / elapsed).toFixed(2)} refunds/second`,
	);

	// Check final root balance
	const finalRootBalance = await publicClient.getBalance({
		address: rootAccount.address,
	});
	console.log(`\nFinal root balance: ${formatEther(finalRootBalance)} ETH`);
}

main().catch(console.error);
