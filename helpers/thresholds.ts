// Threshold configurations for submit/confirm benchmarking
// These can be customized based on the target blockchain performance

/**
 * Threshold configuration for a blockchain type
 */
interface BlockchainThreshold {
	submit: Record<string, string[]>;
	confirm: Record<string, string[]>;
}

/**
 * Blockchain type
 */
type BlockchainType = "ethereum" | "l2" | "l3" | "dev";
type BlockchainThresholdsType = Record<BlockchainType, BlockchainThreshold>;

/**
 * Thresholds configuration type
 */
type ThresholdsConfig = Record<string, string[]>;

/**
 * Default thresholds for different blockchain types
 */
export const BLOCKCHAIN_THRESHOLDS: BlockchainThresholdsType = {
	// Ethereum mainnet
	ethereum: {
		submit: {
			"tx_submit_latency_ms{phase:hold}": ["p(95)<1000", "p(99)<2000"],
			tx_submit_errors: ["rate<0.01"], // Less than 1% error rate
		},
		confirm: {
			"tx_confirm_latency_ms{phase:hold}": ["p(95)<30000", "p(99)<60000"], // ~12s block time
			tx_confirm_timeouts: ["rate<0.05"], // Less than 5% timeout rate
		},
	},

	// Layer 2 solutions (Arbitrum, Optimism, Polygon)
	l2: {
		submit: {
			"tx_submit_latency_ms{phase:hold}": ["p(95)<500", "p(99)<1000"],
			tx_submit_errors: ["rate<0.01"],
		},
		confirm: {
			"tx_confirm_latency_ms{phase:hold}": ["p(95)<5000", "p(99)<10000"], // ~1-2s block time
			tx_confirm_timeouts: ["rate<0.02"],
		},
	},

	// Layer 3 / Fast rollups
	l3: {
		submit: {
			"tx_submit_latency_ms{phase:hold}": ["p(95)<300", "p(99)<600"],
			tx_submit_errors: ["rate<0.005"],
		},
		confirm: {
			"tx_confirm_latency_ms{phase:hold}": ["p(95)<2000", "p(99)<4000"], // Sub-second block time
			tx_confirm_timeouts: ["rate<0.01"],
		},
	},

	// Development/Test networks
	dev: {
		submit: {
			"tx_submit_latency_ms{phase:hold}": ["p(95)<200", "p(99)<500"],
			tx_submit_errors: ["rate<0.02"],
		},
		confirm: {
			"tx_confirm_latency_ms{phase:hold}": ["p(95)<1000", "p(99)<3000"],
			tx_confirm_timeouts: ["rate<0.05"],
		},
	},
};

/**
 * Queue and coordination thresholds (universal)
 */
export const COORDINATION_THRESHOLDS: ThresholdsConfig = {
	handoff_latency_ms: ["p(95)<10", "p(99)<50"], // Queue handoff should be <10ms
	tick_skew_ms: ["p(95)<100", "p(99)<500"], // Scheduling precision
	queue_push_failures: ["rate<0.001"], // Queue should rarely be full
	queue_pop_timeouts: ["rate<0.1"], // Some timeouts are normal during low load
	nonce_refreshes: ["rate<0.05"], // Occasional nonce issues are acceptable
	nonce_errors: ["rate<0.01"], // Persistent nonce errors indicate problems
};

/**
 * Get thresholds configuration for the specified blockchain type
 * @param blockchainType - Type of blockchain ('ethereum', 'l2', 'l3', 'dev')
 * @returns Complete thresholds configuration
 */
export function getThresholds(
	blockchainType: BlockchainType = "dev",
): ThresholdsConfig {
	const chainThresholds =
		BLOCKCHAIN_THRESHOLDS[blockchainType] || BLOCKCHAIN_THRESHOLDS.dev;

	return {
		...chainThresholds.submit,
		...chainThresholds.confirm,
		...COORDINATION_THRESHOLDS,
	};
}

/**
 * Get custom thresholds from environment variables
 * @returns Custom thresholds or empty object
 */
export function getCustomThresholds(): ThresholdsConfig {
	const customThresholds: ThresholdsConfig = {};
	const thresholdPrefix = "THRESHOLD_";

	for (const [key, value] of Object.entries(__ENV)) {
		if (key.startsWith(thresholdPrefix)) {
			const metricName = key.substring(thresholdPrefix.length).toLowerCase();
			try {
				customThresholds[metricName] = JSON.parse(value as string);
			} catch (_error) {
				console.warn(`⚠️ Invalid threshold format for ${key}: ${value}`);
			}
		}
	}

	return customThresholds;
}

/**
 * Merge default and custom thresholds
 * @param blockchainType - Target blockchain type
 * @returns Final thresholds configuration
 */
export function buildThresholds(
	blockchainType: BlockchainType,
): ThresholdsConfig {
	const defaultThresholds = getThresholds(blockchainType);
	const customThresholds = getCustomThresholds();

	// Custom thresholds override defaults
	const finalThresholds = { ...defaultThresholds, ...customThresholds };

	console.log(
		`📊 Thresholds configured for blockchain type: ${blockchainType}`,
	);
	console.log(
		`📊 Active thresholds: ${Object.keys(finalThresholds).length} metrics`,
	);

	return finalThresholds;
}
