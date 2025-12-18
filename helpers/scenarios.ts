// Median time to mine considered at 0.3.
const MEDIAN_ITERATION_DURATION = 0.3;
const BUFFER = 2;
// RATE in User Operations Per Second (UOPS)
const RATE = Number(__ENV.RATE) || 500;
const SCENARIO_TYPE = __ENV.SCENARIO_TYPE || "stress";
const BATCH_SIZE = Number(__ENV.BATCH_SIZE) || 1;
// EFFECTIVE_RATE is k6 rate, i.e. transaction sent per second
const EFFECTIVE_RATE = Math.floor(RATE / BATCH_SIZE);
let maxRate = EFFECTIVE_RATE;
if (SCENARIO_TYPE === "stress") {
	// In stress tests, we ramp up to 200% of the target rate, so we need to increase the variance buffer accordingly.
	maxRate *= 2;
}

// preAllocatedVUs = [median_iteration_duration * rate] + constant_for_variance
// see https://grafana.com/docs/k6/latest/using-k6/scenarios/concepts/arrival-rate-vu-allocation/
const preAllocatedVUs =
	Math.ceil(MEDIAN_ITERATION_DURATION * maxRate * BUFFER) + 1;

export const CONFIG = {
	duration: Number(__ENV.DURATION) || 120,
	rate: EFFECTIVE_RATE,
	batchSize: BATCH_SIZE,
	preAllocatedVUs: preAllocatedVUs,
	maxVUs: preAllocatedVUs,
};

export function getScenarios(scriptName: string) {
	// Calculate effective rate based on batch size (each iteration sends BATCH_SIZE transactions)

	const baseScenario = {
		timeUnit: "1s",
		preAllocatedVUs: preAllocatedVUs,
	};

	let mainScenario: Record<string, unknown>;
	if (SCENARIO_TYPE === "stress") {
		mainScenario = {
			...baseScenario,
			executor: "ramping-arrival-rate",
			startRate: Math.floor(EFFECTIVE_RATE * 0.3), // Start at 30% of the target rate and slowly ramp up to 200%
			stages: [
				{
					target: Math.floor(EFFECTIVE_RATE * 2),
					duration: `${CONFIG.duration}s`,
				},
			],
		};
	} else if (SCENARIO_TYPE === "load") {
		mainScenario = {
			...baseScenario,
			executor: "constant-arrival-rate",
			duration: `${CONFIG.duration}s`,
			rate: EFFECTIVE_RATE,
		};
	} else {
		throw new Error(`Invalid scenario type: ${SCENARIO_TYPE}`);
	}

	// Follow grafana "extract field" format
	const name = `func=${scriptName}, type=${SCENARIO_TYPE}, batch=${BATCH_SIZE}, rate=${EFFECTIVE_RATE}`;

	return {
		tags: {
			name,
			commit: __ENV.COMMIT || "unknown",
		},
		discardResponseBodies: true,
		systemTags: ["scenario"],
		// Threshold for 95th percentile latency to be over 2.5 seconds
		thresholds: {
			[`iteration_duration{scenario:${scriptName}}`]: [
				{
					threshold: "p(95)<2500",
					abortOnFail: SCENARIO_TYPE === "stress",
				},
			],
			// Fail if dropped iterations exceed 10% of emissions at avg rate
			[`dropped_iterations{scenario:${scriptName}}`]: [
				{
					threshold: `count<${(EFFECTIVE_RATE * CONFIG.duration) / 10}`,
					abortOnFail: true,
				},
			],
		},
		scenarios: {
			[scriptName]: mainScenario,
			block_monitor: {
				executor: "shared-iterations",
				exec: "monitor",
				maxDuration: `${CONFIG.duration + (CONFIG.duration < 10 ? 0 : 10)}s`,
				VUs: 1,
			},
		},
	};
}
