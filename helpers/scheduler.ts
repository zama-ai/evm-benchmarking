import { sleep } from "k6";

/**
 * Phase configuration
 */
export interface Phase {
	name: string;
	durationSec: number;
	fromRPS: number;
	toRPS: number;
}

/**
 * Tick object with scheduling metadata
 */
export interface Tick {
	timestamp: number;
	phase: string;
	roundId: string;
	rps: number;
	intervalMs: number;
}

/**
 * Phase configuration for ramped load testing
 * Each phase has: name, durationSec, fromRPS, toRPS
 */
export const DEFAULT_PHASES: Phase[] = [
	{ name: "ramp-up", durationSec: 30, fromRPS: 0.1, toRPS: 1.0 },
	{ name: "hold", durationSec: 60, fromRPS: 1.0, toRPS: 1.0 },
	{ name: "ramp-down", durationSec: 30, fromRPS: 1.0, toRPS: 0.1 },
];

/**
 * Parse phases from environment variable or use defaults
 */
export function parsePhases(): Phase[] {
	const phasesJson = __ENV.PHASES_JSON;
	if (phasesJson) {
		try {
			return JSON.parse(phasesJson) as Phase[];
		} catch (error) {
			console.warn(`❌ Failed to parse PHASES_JSON: ${error}. Using defaults.`);
		}
	}
	return DEFAULT_PHASES;
}

/**
 * Calculate absolute tick timestamps for all phases
 * @param testStartTime - Test start timestamp
 * @param phases - Phase configuration array
 * @returns Array of tick timestamps in milliseconds
 */
export function calculateTickSchedule(
	testStartTime: Date,
	phases: Phase[],
): Tick[] {
	const ticks: Tick[] = [];
	let currentTime = testStartTime.getTime();

	for (const phase of phases) {
		const phaseTicks = calculatePhaseSchedule(currentTime, phase);
		ticks.push(...phaseTicks);
		currentTime += phase.durationSec * 1000;
	}

	return ticks;
}

/**
 * Calculate tick schedule for a single phase
 * @param startTimeMs - Phase start time in milliseconds
 * @param phase - Phase configuration
 * @returns Array of tick objects with timestamp and metadata
 */
function calculatePhaseSchedule(startTimeMs: number, phase: Phase): Tick[] {
	const ticks: Tick[] = [];
	const { name, durationSec, fromRPS, toRPS } = phase;
	const durationMs = durationSec * 1000;

	let currentTime = startTimeMs;
	let roundId = 1;

	while (currentTime < startTimeMs + durationMs) {
		// Calculate current RPS based on linear interpolation
		const progress = (currentTime - startTimeMs) / durationMs;
		const currentRPS = fromRPS + (toRPS - fromRPS) * progress;

		// Calculate interval between rounds (1 / RPS)
		const intervalMs = 1000 / currentRPS;

		ticks.push({
			timestamp: Math.round(currentTime),
			phase: name,
			roundId: `r-${String(roundId).padStart(5, "0")}`,
			rps: currentRPS,
			intervalMs: intervalMs,
		});

		currentTime += intervalMs;
		roundId++;
	}

	return ticks;
}

/**
 * Get the next tick for the current time
 * @param currentTimeMs - Current time in milliseconds
 * @param tickSchedule - Pre-calculated tick schedule
 * @returns Next tick object or null if test is complete
 */
export function getNextTick(
	currentTimeMs: number,
	tickSchedule: Tick[],
): Tick | null {
	// Find the next tick that hasn't occurred yet
	for (const tick of tickSchedule) {
		if (tick.timestamp >= currentTimeMs) {
			return tick;
		}
	}
	return null; // Test is complete
}

/**
 * Sleep until the specified tick time
 * @param tick - Tick object with timestamp
 * @returns Actual skew in milliseconds (positive = late, negative = early)
 */
export function sleepUntilTick(tick: Tick): number {
	const now = Date.now();
	const sleepTime = tick.timestamp - now;

	if (sleepTime > 0) {
		// Sleep until tick time
		const sleepSeconds = sleepTime / 1000;
		sleep(sleepSeconds);
	}

	// Calculate actual skew
	const actualTime = Date.now();
	return actualTime - tick.timestamp;
}

/**
 * Get current phase name from tick schedule
 * @param currentTimeMs - Current time in milliseconds
 * @param tickSchedule - Pre-calculated tick schedule
 * @returns Current phase name or "complete"
 */
export function getCurrentPhase(
	currentTimeMs: number,
	tickSchedule: Tick[],
): string {
	// Find the most recent tick
	let currentPhase = "startup";
	for (const tick of tickSchedule) {
		if (tick.timestamp <= currentTimeMs) {
			currentPhase = tick.phase;
		} else {
			break;
		}
	}

	// Check if test is complete
	const lastTick = tickSchedule[tickSchedule.length - 1];
	if (lastTick && currentTimeMs > lastTick.timestamp + 5000) {
		// 5s buffer
		return "complete";
	}

	return currentPhase;
}
