import { sleep } from "k6";
import exec, { instance } from "k6/execution";
import { initializeClient } from "./init.ts";
import { CONFIG } from "./scenarios.ts";

/**
 * Converts a duration string like '1h3m5s' into milliseconds.
 * Supports any combination of hours, minutes, and seconds.
 * Example: "1h3m5s" => 3785 seconds => 3785000 milliseconds
 */
export function parseDurationToMs(duration: string): number {
	const regex = /(\d+)([hms])/g;
	let totalMilliseconds = 0;
	let match: RegExpExecArray | null;
	match = regex.exec(duration);
	while (match !== null) {
		const value = Number(match[1]);
		const unit = match[2];
		if (unit === "h") {
			totalMilliseconds += value * 60 * 60 * 1000;
		} else if (unit === "m") {
			totalMilliseconds += value * 60 * 1000;
		} else if (unit === "s") {
			totalMilliseconds += value * 1000;
		} else {
			throw new Error(`Invalid unit in duration: ${unit}`);
		}
		match = regex.exec(duration);
	}
	if (totalMilliseconds === 0) {
		throw new Error(`Invalid duration format: ${duration}`);
	}
	return totalMilliseconds;
}

export function monitoringLoop() {
	// Run this VU in a loop to continuously monitor the block height.
	const client = initializeClient();
	const monitorInstance = client.newBlockMonitor(CONFIG.batchSize);
	const scenarioDuration =
		// @ts-expect-error
		exec.test.options?.scenarios?.block_monitor?.maxDuration;
	const scenarioDurationMilliseconds = parseDurationToMs(scenarioDuration);
	while (scenarioDurationMilliseconds > instance.currentTestRunDuration) {
		monitorInstance.processBlockEvent();
		sleep(0.1);
	}
	sleep(0.5);
}
