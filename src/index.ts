import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { GitHubHandler } from "./github-handler";
import {
	createOctokit,
	getFile,
	createOrUpdateFile,
	deleteFile,
} from "./github/index.js";
import type { Props } from "./utils";

export class GitHubMCP extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "GitHub MCP",
		version: "0.1.0",
	});

	private handleError(error: unknown) {
		return {
			content: [
				{
					type: "text" as const,
					text: `Error: ${error instanceof Error ? error.message : String(error)}`,
				},
			],
			isError: true,
		};
	}

	async init() {
		this.server.tool(
			"file_get",
			"Get file content or directory listing from a GitHub repository. " +
				"For files, returns decoded text content. " +
				"For directories, returns an entry list. " +
				"Only supports files up to 1 MB.",
			{
				owner: z.string().describe("Repository owner (user or organization)"),
				repo: z.string().describe("Repository name"),
				path: z.string().describe("File or directory path"),
			},
			async ({ owner, repo, path }) => {
				try {
					const octokit = createOctokit(this.props!.accessToken);
					const result = await getFile(octokit, owner, repo, path);
					return {
						content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
					};
				} catch (error) {
					return this.handleError(error);
				}
			},
		);

		this.server.tool(
			"file_create_or_update",
			"Create a new file or update an existing file on the default branch. " +
				"Commits directly to the default branch. " +
				"If the file already exists, its SHA is auto-detected for update.",
			{
				owner: z.string().describe("Repository owner (user or organization)"),
				repo: z.string().describe("Repository name"),
				path: z.string().describe("File path to create or update"),
				content: z.string().describe("File content (UTF-8 text)"),
				message: z.string().describe("Commit message"),
			},
			async ({ owner, repo, path, content, message }) => {
				try {
					const octokit = createOctokit(this.props!.accessToken);
					const result = await createOrUpdateFile(
						octokit,
						owner,
						repo,
						path,
						content,
						message,
					);
					return {
						content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
					};
				} catch (error) {
					return this.handleError(error);
				}
			},
		);

		this.server.tool(
			"file_delete",
			"Delete a file from the default branch. " +
				"Commits the deletion directly to the default branch. " +
				"The file SHA is auto-detected.",
			{
				owner: z.string().describe("Repository owner (user or organization)"),
				repo: z.string().describe("Repository name"),
				path: z.string().describe("File path to delete"),
				message: z.string().describe("Commit message"),
			},
			async ({ owner, repo, path, message }) => {
				try {
					const octokit = createOctokit(this.props!.accessToken);
					const result = await deleteFile(octokit, owner, repo, path, message);
					return {
						content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
					};
				} catch (error) {
					return this.handleError(error);
				}
			},
		);
	}
}

export default new OAuthProvider({
	apiHandler: GitHubMCP.serve("/mcp"),
	apiRoute: "/mcp",
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/register",
	defaultHandler: GitHubHandler as any,
	tokenEndpoint: "/token",
});
