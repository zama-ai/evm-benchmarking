// Enhanced metrics for submit/confirm benchmarking
import { Counter, Gauge, Trend } from "k6/metrics";

/**
 * Metric tags interface
 */
interface MetricTags {
	[key: string]: string;
}

// Submit latency metrics
export const submitLatency = new Trend("tx_submit_latency_ms", true);
export const submitErrors = new Counter("tx_submit_errors");
export const submitSuccess = new Counter("tx_submit_success");

// Confirm latency metrics
export const confirmLatency = new Trend("tx_confirm_latency_ms", true);
export const confirmErrors = new Counter("tx_confirm_errors");
export const confirmSuccess = new Counter("tx_confirm_success");
export const confirmTimeouts = new Counter("tx_confirm_timeouts");

// Queue metrics
export const queueDepth = new Gauge("queue_depth");
export const queuePushFailures = new Counter("queue_push_failures");
export const queuePopTimeouts = new Counter("queue_pop_timeouts");

// Timing precision metrics
export const tickSkew = new Trend("tick_skew_ms", true);
export const handoffLatency = new Trend("handoff_latency_ms", true);

// Nonce management metrics
export const nonceRefreshes = new Counter("nonce_refreshes");
export const nonceErrors = new Counter("nonce_errors");

// Round/phase coordination metrics
export const roundsCompleted = new Counter("rounds_completed");
export const phaseTransitions = new Counter("phase_transitions");

/**
 * Record submit latency with tags
 * @param latencyMs - Submit latency in milliseconds
 * @param tags - Metric tags (party, phase, round_id, etc.)
 */
export function recordSubmitLatency(
	latencyMs: number,
	tags: MetricTags = {},
): void {
	submitLatency.add(latencyMs, tags);
	submitSuccess.add(1, tags);
}

/**
 * Record submit error with tags
 * @param reason - Error reason
 * @param tags - Metric tags
 */
export function recordSubmitError(reason: string, tags: MetricTags = {}): void {
	const errorTags = { ...tags, reason };
	submitErrors.add(1, errorTags);
}

/**
 * Record confirm latency with tags
 * @param latencyMs - Confirm latency in milliseconds
 * @param tags - Metric tags (party, phase, round_id, etc.)
 */
export function recordConfirmLatency(
	latencyMs: number,
	tags: MetricTags = {},
): void {
	confirmLatency.add(latencyMs, tags);
	confirmSuccess.add(1, tags);
}

/**
 * Record confirm error with tags
 * @param reason - Error reason ("timeout", "replaced", "dropped", etc.)
 * @param tags - Metric tags
 */
export function recordConfirmError(
	reason: string,
	tags: MetricTags = {},
): void {
	const errorTags = { ...tags, reason };
	confirmErrors.add(1, errorTags);

	if (reason === "timeout") {
		confirmTimeouts.add(1, tags);
	}
}

/**
 * Record tick timing precision
 * @param skewMs - Tick skew in milliseconds (positive = late)
 * @param tags - Metric tags (party, phase, round_id)
 */
export function recordTickSkew(skewMs: number, tags: MetricTags = {}): void {
	tickSkew.add(skewMs, tags);
}

/**
 * Record queue handoff timing
 * @param sentAt - Message sent timestamp
 * @param receivedAt - Message received timestamp
 * @param tags - Metric tags (party, phase)
 */
export function recordHandoffLatency(
	sentAt: number,
	receivedAt: number,
	tags: MetricTags = {},
): void {
	const latencyMs = receivedAt - sentAt;
	handoffLatency.add(latencyMs, tags);
}

/**
 * Record queue push failure
 * @param partyIndex - Party index
 * @param tags - Additional tags
 */
export function recordQueuePushFailure(
	partyIndex: number,
	tags: MetricTags = {},
): void {
	const failureTags = { ...tags, party: partyIndex.toString() };
	queuePushFailures.add(1, failureTags);
}

/**
 * Record queue pop timeout
 * @param partyIndex - Party index
 * @param tags - Additional tags
 */
export function recordQueuePopTimeout(
	partyIndex: number,
	tags: MetricTags = {},
): void {
	const timeoutTags = { ...tags, party: partyIndex.toString() };
	queuePopTimeouts.add(1, timeoutTags);
}

/**
 * Update queue depth gauge
 * @param partyIndex - Party index
 * @param depth - Current queue depth
 * @param tags - Additional tags
 */
export function updateQueueDepth(
	partyIndex: number,
	depth: number,
	tags: MetricTags = {},
): void {
	const depthTags = { ...tags, party: partyIndex.toString() };
	queueDepth.add(depth, depthTags);
}

/**
 * Record nonce refresh event
 * @param partyIndex - Party index
 * @param reason - Refresh reason ("too_low", "replacement", etc.)
 * @param tags - Additional tags
 */
export function recordNonceRefresh(
	partyIndex: number,
	reason: string,
	tags: MetricTags = {},
): void {
	const refreshTags = { ...tags, party: partyIndex.toString(), reason };
	nonceRefreshes.add(1, refreshTags);
}

/**
 * Record nonce error
 * @param partyIndex - Party index
 * @param error - Error description
 * @param tags - Additional tags
 */
export function recordNonceError(
	partyIndex: number,
	error: string,
	tags: MetricTags = {},
): void {
	const errorTags = { ...tags, party: partyIndex.toString(), error };
	nonceErrors.add(1, errorTags);
}

/**
 * Record round completion
 * @param roundId - Round identifier
 * @param tags - Additional tags (phase, etc.)
 */
export function recordRoundCompleted(
	roundId: string,
	tags: MetricTags = {},
): void {
	const roundTags = { ...tags, round_id: roundId };
	roundsCompleted.add(1, roundTags);
}

/**
 * Record phase transition
 * @param fromPhase - Previous phase
 * @param toPhase - New phase
 * @param tags - Additional tags
 */
export function recordPhaseTransition(
	fromPhase: string,
	toPhase: string,
	tags: MetricTags = {},
): void {
	const transitionTags = { ...tags, from_phase: fromPhase, to_phase: toPhase };
	phaseTransitions.add(1, transitionTags);
}
