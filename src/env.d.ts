// Secrets set via `wrangler secret put`
declare namespace Cloudflare {
	interface Env {
		GITHUB_CLIENT_ID: string;
		GITHUB_CLIENT_SECRET: string;
		COOKIE_ENCRYPTION_KEY: string;
	}
}
