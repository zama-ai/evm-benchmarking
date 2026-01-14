import { textSummary } from "https://jslib.k6.io/k6-summary/0.0.2/index.js";
import { sleep } from "k6";
import eth from "k6/x/ethereum";

const RPC_URL = __ENV.ETH_RPC_URL || "http://127.0.0.1:8545";
const START_BLOCK = __ENV.START_BLOCK ? Number(__ENV.START_BLOCK) : null;
const END_BLOCK_ENV = __ENV.END_BLOCK ? Number(__ENV.END_BLOCK) : null;
const BATCH_SIZE = Number(__ENV.BATCH_SIZE) || 1;
const LOG_INTERVAL = Number(__ENV.LOG_INTERVAL) || 100;
const NUM_VUS = Number(__ENV.NUM_VUS) || 4;

export const options = {
	scenarios: {
		historical_monitor: {
			executor: "per-vu-iterations",
			iterations: 1,
			vus: NUM_VUS,
			maxDuration: "24h",
		},
	},
	tags: {
		name: "historical_monitoring",
	},
};

export default function () {
	const client = new eth.Client({ url: RPC_URL });

	if (START_BLOCK === null || isNaN(START_BLOCK)) {
		throw new Error(
			"START_BLOCK environment variable is required (e.g., START_BLOCK=1000)",
		);
	}

	// Resolve END_BLOCK to latest if not specified
	const endBlock = END_BLOCK_ENV ?? client.blockNumber();

	if (START_BLOCK > endBlock) {
		throw new Error(
			`START_BLOCK (${START_BLOCK}) cannot be greater than END_BLOCK (${endBlock})`,
		);
	}

	const totalBlocks = endBlock - START_BLOCK + 1;

	// Calculate this VU's block range
	const vuId = __VU - 1; // 0-indexed
	const blocksPerVU = Math.ceil(totalBlocks / NUM_VUS);
	const vuStartBlock = START_BLOCK + vuId * blocksPerVU;
	const vuEndBlock = Math.min(vuStartBlock + blocksPerVU - 1, endBlock);

	// Skip if this VU has no blocks to process (more VUs than blocks)
	if (vuStartBlock > endBlock) {
		console.log(`VU ${__VU}: No blocks to process (range exhausted)`);
		return;
	}

	const vuBlockCount = vuEndBlock - vuStartBlock + 1;
	console.log(
		`VU ${__VU}: Processing blocks ${vuStartBlock} to ${vuEndBlock} (${vuBlockCount} blocks)`,
	);

	const iterator = client.newHistoricalBlockIterator(
		BATCH_SIZE,
		vuStartBlock,
		vuEndBlock,
	);

	let processedBlocks = 0;
	const startTime = Date.now();

	while (iterator.processNextBlock()) {
		processedBlocks++;

		// Progress logging (per VU)
		if (processedBlocks % LOG_INTERVAL === 0) {
			const progress = Math.round((processedBlocks / vuBlockCount) * 100);
			const elapsed = (Date.now() - startTime) / 1000;
			const rate = processedBlocks / elapsed;
			const eta = Math.round((vuBlockCount - processedBlocks) / rate);
			console.log(
				`VU ${__VU}: ${progress}% (${processedBlocks}/${vuBlockCount}) - ${rate.toFixed(1)} blocks/s - ETA: ${eta}s`,
			);
		}

		// Small sleep to avoid overwhelming the RPC
		sleep(0.01);
	}

	const totalTime = (Date.now() - startTime) / 1000;
	console.log(
		`VU ${__VU}: Complete - ${processedBlocks} blocks in ${totalTime.toFixed(1)}s (${(processedBlocks / totalTime).toFixed(1)} blocks/s)`,
	);
}

export function handleSummary(
	data: Record<string, unknown>,
): Record<string, string> {
	return {
		stdout: textSummary(data, { indent: " ", enableColors: true }),
		"historical-monitoring-results.json": JSON.stringify(data, null, 2),
	};
}
