declare module "k6/x/ethereum" {
	export type EthHash = string; // 0x-prefixed 64 char hex
	export type EthAddress = string; // 0x-prefixed 40 char hex
	export type EthBigInt = string; // decimal or 0x-prefixed hex

	export interface Options {
		url: string;
		privateKey?: string; // hex without 0x or with 0x; required for signing methods
		receiptTimeout?: number; // milliseconds, default 300000 (5 min) - timeout for receipt polling
		receiptPollInterval?: number; // milliseconds, default 100 - interval between receipt poll attempts
	}

	// EIP-2930 access list entry
	export interface AccessTuple {
		address: string; // hex address
		storageKeys: string[]; // hex storage slot keys
	}

	export interface Transaction {
		from?: string;
		to: string;
		input?: Uint8Array;
		// NOTE: numeric fields must fit JS safe integer range.
		gasPrice?: number;
		gasFeeCap?: number;
		gasTipCap?: number;
		gas?: number;
		value?: number;
		nonce?: number;
		accessList?: AccessTuple[]; // EIP-2930 access list
	}

	// Receipt with proper js struct tags for k6's Go-JS bridge (camelCase field names)
	export interface Receipt {
		type: number;
		status: number;
		cumulativeGasUsed: number;
		transactionHash: string; // hex hash
		contractAddress?: string; // hex address, present for contract creation txs
		gasUsed: number;
		effectiveGasPrice?: number;
		blockHash: string; // hex hash
		blockNumber: number;
		transactionIndex: number;
		logs: Log[];
		logsBloom: ArrayBuffer; // []byte
	}

	// Log with proper js struct tags for k6's Go-JS bridge (camelCase field names)
	export interface Log {
		removed: boolean;
		logIndex: number;
		transactionIndex: number;
		transactionHash: string; // hex hash
		blockHash: string; // hex hash
		blockNumber: number;
		address: string; // hex address
		topics: string[]; // hex hashes
		data: string; // hex bytes
	}

	export interface TxnOpts {
		// NOTE: numeric fields must fit JS safe integer range.
		value?: number;
		gasPrice?: number;
		gasLimit?: number;
		nonce?: number;
		accessList?: AccessTuple[] | undefined; // EIP-2930 access list
	}

	export interface Call3 {
		target: string;
		allowFailure: boolean;
		calldata: Uint8Array;
	}

	export interface Call3Value {
		target: string;
		allowFailure: boolean;
		value: number;
		calldata: Uint8Array;
	}

	// Block with proper js struct tags for k6's Go-JS bridge (camelCase field names)
	export interface Block {
		number: number;
		hash: string; // hex hash
		parentHash: string; // hex hash
		sha3Uncles: string; // hex hash
		transactionsRoot: string; // hex hash
		stateRoot: string; // hex hash
		receiptsRoot: string; // hex hash
		miner: string; // hex address
		difficulty: string; // big int as string
		extraData: string; // hex bytes
		gasLimit: number;
		gasUsed: number;
		timestamp: number;
		mixHash: string; // hex hash
		nonce: number;
		baseFeePerGas?: string; // big int as string (EIP-1559)
		transactions: BlockTransaction[];
	}

	// Transaction within a block
	export interface BlockTransaction {
		type: number;
		hash: string; // hex hash
		from?: string; // hex address (derived from signature)
		to?: string; // hex address
		input: string; // hex bytes
		gas: number;
		gasPrice?: string; // big int as string
		maxFeePerGas?: string; // big int as string (EIP-1559)
		maxPriorityFeePerGas?: string; // big int as string (EIP-1559)
		value: string; // big int as string
		nonce: number;
		chainId?: number;
		v: string; // hex bytes
		r: string; // hex bytes
		s: string; // hex bytes
	}

	export class Client {
		constructor(opts: Options);
		// Set the private key for the client, updating the address accordingly.
		setPrivateKey(privateKey: string): void;
		gasPrice(): number;
		// blockNumber: use null/undefined for latest, or a specific block number
		// Throws if address is invalid.
		getBalance(address: string, blockNumber?: number | null): number;
		blockNumber(): number;
		// number: use null/undefined for latest block
		getBlockByNumber(number?: number | null): Block;
		// Throws if address is invalid.
		getNonce(address: string): number;
		estimateGas(tx: Transaction): number;
		sendTransaction(tx: Transaction): string;
		sendRawTransaction(tx: Transaction): string;
		// Synchronously signs, sends, and waits for the mined receipt via eth_sendRawTransactionSync.
		sendTransactionSync(tx: Transaction): Receipt;
		// Signs, sends via eth_sendRawTransaction, and polls for the receipt.
		// Same retry logic as sendTransactionSync but uses legacy RPC methods.
		sendTransactionAndWaitReceipt(tx: Transaction): Receipt;
		batchCallSync(
			multicallAddress: string,
			calls: Call3[],
			opts: TxnOpts,
		): Receipt;
		batchCallValueSync(
			multicallAddress: string,
			calls: Call3Value[],
			opts: TxnOpts,
		): Receipt;
		getTransactionReceipt(hash: string): Receipt;
		waitForTransactionReceipt(hash: string): Promise<Receipt>;
		accounts(): string[];
		getWallet(): WalletInfo;
		newContract(address: string, abi: string): Contract;
		deployContract(abi: string, bytecode: string, ...args: any[]): Receipt;
		newBlockMonitor(batchSize: number): BlockMonitor;
		// Creates an iterator for processing historical blocks in a range.
		newHistoricalBlockIterator(
			batchSize: number,
			startBlock: number,
			endBlock: number,
		): HistoricalBlockIterator;
		// Raw JSON-RPC call
		call(method: string, ...params: any[]): any;
		print(msg: string): void;
	}

	export interface BlockMonitor {
		processBlockEvent(): void;
	}

	// Iterator for processing historical blocks and emitting metrics.
	export interface HistoricalBlockIterator {
		// Fetches the next block and emits metrics. Returns true if more blocks remain.
		processNextBlock(): boolean;
		// Returns the current block number being processed.
		getCurrentBlock(): number;
		// Returns whether all blocks have been processed.
		isDone(): boolean;
	}

	export interface WalletInfo {
		address: string;
		privateKey: string; // hex without 0x
	}

	export interface Contract {
		call(method: string, ...args: any[]): any;
		txn(method: string, opts: TxnOpts, ...args: any[]): string; // tx hash
		// Synchronous variant: encodes and sends the contract call using raw sync RPC and returns the mined receipt.
		txnSync(method: string, opts: TxnOpts, ...args: any[]): Receipt;
		// Sends via eth_sendRawTransaction and polls for the receipt.
		// Same retry logic as txnSync but uses standard RPC methods.
		txnAndWaitReceipt(method: string, opts: TxnOpts, ...args: any[]): Receipt;
		encodeABI(method: string, ...args: any[]): Uint8Array;
	}

	const _default: {
		Client: new (opts: Options) => Client;
	};
	export default _default;
}

declare module "k6/x/ethereum/wallet" {
	export interface Account {
		privateKey: string; // hex without 0x
		address: string;
	}

	export function generateKey(): Account;
	export function accountsFromMnemonic(
		mnemonic: string,
		count?: number,
	): Account[];
	export function accountFromPrivateKey(privateKeyHex: string): Account;

	// Cryptographic utilities for computing storage slots
	export function keccak256(inputHex: string): string;
	export function computeMappingSlot(key: string, baseSlot: number): string;
	export function computeNestedMappingSlot(
		key1: string,
		key2: string,
		baseSlot: number,
	): string;
}
