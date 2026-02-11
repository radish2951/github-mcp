# GitHub MCP Server

GitHub APIをMCPツールとして公開するリモートMCPサーバ。Cloudflare Workers上で動作し、GitHub OAuthによるユーザ認証を行う。

## ツール

| ツール | 概要 |
|--------|------|
| `file_get` | ファイル内容取得、ディレクトリの場合は一覧を返す (1MBまで) |
| `file_create_or_update` | ファイル作成/更新 (デフォルトブランチに直コミット) |
| `file_delete` | ファイル削除 (デフォルトブランチに直コミット) |

## セットアップ

### 1. GitHub OAuth App 作成

1. GitHub Settings > Developer settings > OAuth Apps > New OAuth App
2. 以下を設定
   - Application name: 任意
   - Homepage URL: `https://<worker-name>.<account>.workers.dev`
   - Authorization callback URL: `https://<worker-name>.<account>.workers.dev/callback`
3. Client ID と Client Secret を控える

### 2. Cloudflare KV 作成

```bash
npx wrangler kv namespace create OAUTH_KV
```

出力されたIDを `wrangler.jsonc` の `kv_namespaces[0].id` に設定する。

### 3. Secrets 設定

```bash
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
npx wrangler secret put COOKIE_ENCRYPTION_KEY
```

`COOKIE_ENCRYPTION_KEY` にはランダムな文字列を設定する (`openssl rand -hex 32` など)。

### 4. デプロイ

```bash
pnpm run deploy
```

## ローカル開発

```bash
# .dev.vars に Secrets を設定
cat > .dev.vars << 'EOF'
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
COOKIE_ENCRYPTION_KEY=your_random_key
EOF

pnpm run dev
```

### MCP Inspector で接続テスト

```bash
npx @modelcontextprotocol/inspector@latest
```

URL に `http://localhost:8788/mcp` を入力して接続する。

## 技術スタック

- Cloudflare Workers + Durable Objects
- `@cloudflare/workers-oauth-provider` (OAuth 2.1)
- `agents` (MCP Agent SDK)
- `octokit` (GitHub API)
- `hono` (OAuthハンドラ)
- `zod` (スキーマバリデーション)
