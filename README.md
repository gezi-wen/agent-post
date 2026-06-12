# Agent Post

**AI agent identity + communication protocol.** File inbox + Ed25519 identity + group routing.

Email's async model + Bitcoin's self-sovereign identity + Signal's signature trust — built for AI agents.
No network, no registry, no CA. Just a filesystem and a keypair.

**AI agent 身份+通信协议**。文件 inbox + Ed25519 身份 + 分组路由。Email 的异步 + Bitcoin 的自有身份 + Signal 的签名可信，为 AI agent 设计。不需要网络、不需要注册中心、不需要 CA。

---

## Quick Start | 快速开始

```bash
# Install (Rust 1.96+)
cargo install agent-post

# Create identity | 创建身份
agent-post init -n "MyAgent" -g "my-group"

# Pair with another agent | 配对
agent-post group create my-group
agent-post pair invite --to <their_id> --group my-group
# ... they accept, you confirm | 对方接受，你确认 ...

# Send signed message | 发签名消息
agent-post send --to <their_id> -c "Hello!"

# Poll inbox | 查收
agent-post poll --group my-group

# Start MCP server (for Claude Code, Cline, etc.)
agent-post mcp
```

---

## Features | 功能

| Feature | 功能 | Description |
|---------|------|-------------|
| **Ed25519 Identity** | Ed25519 身份 | Self-generated keypair. `agent_id = base58(sha256(pubkey)[:16])`. Bitcoin address model — no CA, no registration. |
| **File Inbox** | 文件 inbox | JSONL append-only. POSIX O_APPEND atomic. No network, no daemon. |
| **3-Way Handshake** | 三次握手配对 | Invite → Accept → Confirm. Each step Ed25519-signed. 72h expiry. Tamper-proof. |
| **Group Routing** | 分组路由 | Unicast / Multicast (`group:name`) / Broadcast (`*`). |
| **Key Encryption** | 私钥加密 | Argon2id + AES-256-GCM passphrase protection. |
| **MCP Server** | MCP 服务 | `agent-post mcp` — 13 tools. Claude Code, Cline, Codex native integration. |
| **TypeScript SDK** | TS SDK | `npm install agent-post`. Sage-ready. |
| **File References** | 文件引用 | `file_ref` type. Auto-switches when content > 64KB. |
| **Cross-Group Relay** | 跨组中继 | `agent-post relay --port 9876`. HTTP bridge for groups without shared FS. |
| **Key Revocation** | 密钥吊销 | Pre-signed revocation certificate. Signal-style safety number recovery. |

---

## Architecture | 架构

```
~/.agent-post/
  config.toml              ← global defaults | 全局默认
  identities/              ← Ed25519 identity files | 身份文件
    {agent_id}.json
  groups/
    {group_name}/
      members.toml         ← paired members | 组成员
      routes.toml          ← cross-machine paths + relays | 路由
      inboxes/
        {agent_id}/
          mailbox.jsonl     ← incoming (JSONL) | 来信
          .watermark.json   ← dedup cursor | 去重水位
```

---

## Message Format | 消息格式

```json
{"id":"a1b2c","from":"agent_id","to":"agent_id","type":"text","content":"hello","refs":[],"ts":"2026-06-12T12:00:00Z","sig":"base58-ed25519"}
```

**Signing** | 签名：fields except `sig` → RFC 8785 canonical JSON → SHA-256 → Ed25519 `verify_strict()`.  
**Limit** | 上限：64KB per message. Larger content → `file_ref` type.  
**Dedup** | 去重：per-sender watermark (`last_ts` + `seen_ids`).

---

## MCP Tools

13 tools exposed via `agent-post mcp`:

| Tool | Description |
|------|-------------|
| `init` | Create identity with optional passphrase encryption |
| `identity_show` / `identity_list` | View / list identities |
| `pair_invite` / `pair_check` / `pair_accept` / `pair_reject` / `pair_confirm` | 3-way handshake pairing |
| `send_message` | Sign and send message (unicast/multicast/broadcast) |
| `poll_inbox` | Poll inbox, verify signatures, return new messages |
| `group_create` / `group_list` / `group_info` | Group management |

Configure in `~/.claude/settings.json`:

```json
"mcpServers": {
  "agent-post": {
    "command": "/path/to/agent-post",
    "args": ["mcp"]
  }
}
```

---

## TypeScript SDK | TS 开发包

```typescript
import { AgentPostClient } from "agent-post";

const ap = new AgentPostClient({ binaryPath: "agent-post" });
await ap.init({ name: "Sage", group: "dev" });
await ap.send({ to: "agent_id", content: "hello" });
const msgs = await ap.poll();
```

Wraps the agent-post binary via stdio JSON-RPC. All 13 MCP tools exposed as typed async methods.

---

## Protocol Spec | 协议规范

See [docs/protocol-spec.md](docs/protocol-spec.md) — language-agnostic specification.

Any implementation following this spec is Agent Post compatible — regardless of language, runtime, or platform.

详见 [docs/protocol-spec.md](docs/protocol-spec.md) —— 语言无关的协议规范。任何语言按此规范实现，均可互操作。

---

## Design | 设计理念

Agent Post fills the gap between protocols:

| Protocol | Scope | Missing |
|----------|-------|---------|
| **MCP** | agent ↔ tool | Not agent-agent communication |
| **A2A** | agent ↔ agent (network) | Requires HTTP, DNS, OAuth — no offline |
| **SAMP** | agent ↔ agent (file) | No cryptographic identity |
| **OpenFused** | agent ↔ agent (file+encryption) | No group routing, no pairing handshake |

Agent Post: **file inbox + cryptographic identity + group routing, all three in one.**

---

## License | 协议

Apache 2.0
