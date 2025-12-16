import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.2/index.js";
import { fail } from "k6";
import type { Call3 } from "k6/x/ethereum";
import { initializeClient, maybeDeployMulticall3 } from "../helpers/init.ts";
import { monitoringLoop } from "../helpers/monitoring.ts";
import { CONFIG, getScenarios } from "../helpers/scenarios.ts";

const TOKEN_NAME = "MyToken";
const TOKEN_SYMBOL = "MTK";
const TOKEN_INITIAL_SUPPLY = 1_000_000_000_000_000n;
const TOKEN_TRANSFER_AMOUNT = 1n;
const TOKEN_ABI = String(open("../contracts/out/MyToken.sol/MyToken.abi.json"));
const TOKEN_BIN = String(open("../contracts/out/MyToken.sol/MyToken.bin"));

export const options = getScenarios("erc20-transfer");

const vuClient = initializeClient();
const SENDER_ADDRESS = vuClient.getWallet().address;

interface SetupData {
	tokenAddress: string;
	multicallAddress: string | null;
	gasPrice: number;
}

export function setup(): SetupData {
	// Deploy ERC20 once; mint initial supply to deployer (senderAddress)
	const tokenReceipt = vuClient.deployContract(
		TOKEN_ABI,
		TOKEN_BIN,
		TOKEN_NAME,
		TOKEN_SYMBOL,
		TOKEN_INITIAL_SUPPLY,
	);
	const tokenAddress = String(tokenReceipt.contractAddress);

	const multicallAddress = maybeDeployMulticall3(vuClient);

	const gasPrice = vuClient.gasPrice();
	if (multicallAddress) {
		// Give infinite approval to the Multicall contract
		const tokenContract = vuClient.newContract(tokenAddress, TOKEN_ABI);
		const _receipt = tokenContract.txnSync(
			"approve",
			{ gasPrice: gasPrice },
			multicallAddress,
			TOKEN_INITIAL_SUPPLY,
		);
		if (_receipt.status !== 1) {
			fail(`Approval transaction failed with status: ${_receipt.status}`);
		}
	}

	return {
		tokenAddress,
		multicallAddress,
		gasPrice,
	};
}

export default function ({
	tokenAddress,
	multicallAddress,
	gasPrice,
}: SetupData) {
	const tokenContract = vuClient.newContract(tokenAddress, TOKEN_ABI);

	if (multicallAddress) {
		// Build batch of transfer calls
		const calls: Call3[] = [];
		for (let i = 0; i < CONFIG.batchSize; i++) {
			// Encode transfer call without sending it
			const calldata = tokenContract.encodeABI(
				"transferFrom",
				SENDER_ADDRESS,
				SENDER_ADDRESS,
				TOKEN_TRANSFER_AMOUNT,
			);

			calls.push({
				target: tokenAddress,
				allowFailure: false,
				calldata: calldata,
			});
		}

		// Send batch via Multicall3
		const _receipt = vuClient.batchCallSync(multicallAddress, calls, {
			gasPrice: gasPrice,
		});
		if (_receipt.status !== 1) {
			fail(`Batch transaction failed with status: ${_receipt.status}`);
		}
	} else {
		// Synchronous contract txn: waits for receipt server-side
		const _receipt = tokenContract.txnSync(
			"transfer",
			{ gasPrice: gasPrice },
			SENDER_ADDRESS,
			TOKEN_TRANSFER_AMOUNT,
		);
		if (_receipt.status !== 1) {
			fail(`Transaction failed with status: ${_receipt.status}`);
		}
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
