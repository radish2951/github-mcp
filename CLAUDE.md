# GitHub MCP Server

GitHub APIのファイル操作をMCPツールとして公開するリモートMCPサーバ。Cloudflare Workers + Durable Objects上で動作する。

## パッケージマネージャ

pnpm を使用する。npm は使わない。

## コマンド

- `pnpm run dev` ローカル起動
- `pnpm run deploy` デプロイ
- `pnpm run type-check` 型チェック
- `pnpm run cf-typegen` wrangler型定義の再生成

## アーキテクチャ

- `src/index.ts` McpAgent定義、3ツール登録、OAuthProvider default export
- `src/github-handler.ts` GitHub OAuthフロー
- `src/utils.ts` OAuth URL構築、トークン交換
- `src/workers-oauth-utils.ts` CSRF保護、state管理、承認ダイアログ
- `src/github/` GitHub API操作 (Octokit)

## OAuth

- GitHub OAuth App (スコープ `repo read:user`)
- GitHub OAuthトークンは期限切れしないため、リフレッシュ処理は不要
- トークンは `props.accessToken` としてMcpAgentに渡される

## コミット規約

1. コミット前に `pnpm run type-check` を実行する
2. コミットメッセージは簡潔に
