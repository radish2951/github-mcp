import { Octokit } from "octokit";

export function createOctokit(accessToken: string): Octokit {
	return new Octokit({ auth: accessToken });
}
