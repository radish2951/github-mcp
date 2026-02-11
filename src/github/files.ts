import type { Octokit } from "octokit";

export type FileEntry = {
	name: string;
	path: string;
	type: "file" | "dir" | "symlink" | "submodule";
	size: number;
	sha: string;
};

export type FileContent = {
	name: string;
	path: string;
	sha: string;
	size: number;
	content: string;
};

export type DirectoryListing = {
	path: string;
	entries: FileEntry[];
};

export type MutationResult = {
	path: string;
	sha: string;
	commitSha: string;
};

function encodeBase64(text: string): string {
	const bytes = new TextEncoder().encode(text);
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

function decodeBase64(base64: string): string {
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return new TextDecoder().decode(bytes);
}

export async function getFile(
	octokit: Octokit,
	owner: string,
	repo: string,
	path: string,
): Promise<FileContent | DirectoryListing> {
	const { data } = await octokit.rest.repos.getContent({ owner, repo, path });

	// Directory
	if (Array.isArray(data)) {
		return {
			path,
			entries: data.map((entry) => ({
				name: entry.name,
				path: entry.path,
				type: entry.type as FileEntry["type"],
				size: entry.size,
				sha: entry.sha,
			})),
		};
	}

	// File
	if (data.type === "file" && "content" in data) {
		return {
			name: data.name,
			path: data.path,
			sha: data.sha,
			size: data.size,
			content: decodeBase64(data.content),
		};
	}

	throw new Error(`Unsupported content type: ${data.type}`);
}

export async function createOrUpdateFile(
	octokit: Octokit,
	owner: string,
	repo: string,
	path: string,
	content: string,
	message: string,
): Promise<MutationResult> {
	// Try to get existing file SHA for update
	let sha: string | undefined;
	try {
		const { data } = await octokit.rest.repos.getContent({ owner, repo, path });
		if (!Array.isArray(data) && data.type === "file") {
			sha = data.sha;
		}
	} catch (error: unknown) {
		if (!(error instanceof Error) || !("status" in error) || error.status !== 404)
			throw error;
		// 404 means new file, no SHA needed
	}

	const { data } = await octokit.rest.repos.createOrUpdateFileContents({
		owner,
		repo,
		path,
		message,
		content: encodeBase64(content),
		sha,
	});

	return {
		path: data.content!.path!,
		sha: data.content!.sha!,
		commitSha: data.commit.sha!,
	};
}

export async function deleteFile(
	octokit: Octokit,
	owner: string,
	repo: string,
	path: string,
	message: string,
): Promise<{ commitSha: string }> {
	// Get file SHA (required for deletion)
	const { data: fileData } = await octokit.rest.repos.getContent({
		owner,
		repo,
		path,
	});
	if (Array.isArray(fileData)) {
		throw new Error(`Cannot delete a directory: ${path}`);
	}

	const { data } = await octokit.rest.repos.deleteFile({
		owner,
		repo,
		path,
		message,
		sha: fileData.sha,
	});

	return { commitSha: data.commit.sha! };
}
