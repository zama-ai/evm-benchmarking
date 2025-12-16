declare module "https://jslib.k6.io/k6-utils/1.2.0/index.js" {
	export function randomIntBetween(min: number, max: number): number;
}

declare module "https://jslib.k6.io/k6-summary/0.0.2/index.js" {
	export function textSummary(
		data: Record<string, unknown>,
		opts?: any,
	): string;
}
