import { monitoringLoop } from "../helpers/monitoring.ts";

const DURATION = __ENV.DURATION || "120";

export const options = {
	scenarios: {
		block_monitor: {
			executor: "shared-iterations",
			exec: "monitor",
			maxDuration: `${DURATION}s`,
			VUs: 1,
		},
	},
};

export default function () {}

export function monitor() {
	monitoringLoop();
}
