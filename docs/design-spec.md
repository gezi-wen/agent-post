# Agent Post — 设计规格

**日期：2026-06-11 · 昼殿**
**状态：立项**

---

## 一、定位

Agent Post 是 AI agent 的身份+通信协议。文件 inbox + Ed25519 身份 + 分组路由，三者合一。

一句话：**Email 的异步性 + Bitcoin 的去中心化身份 + Signal 的签名可信度，为 AI agent 设计。**

---

## 二、为什么需要 Agent Post

### 现有生态的缺口

| 协议 | 定位 | 缺什么 |
|------|------|--------|
| **MCP** | agent↔工具 | 不是 agent 间通信协议 |
| **A2A** | agent↔agent（网络） | 需要 HTTP 端点、服务发现、OAuth |
| **SAMP** | agent↔agent（文件） | 只有 alias 字符串，无密码学身份 |
| **OpenFused** | agent↔agent（文件+加密） | 无分组路由、无跨组桥接 |

Agent Post 填补的空白：**文件 inbox + 密码学身份 + 分组路由，三者合一。** 不要求网络、不要求服务发现、不要求注册中心。

### 核心假设

Agent 之间有**可共享的文件系统**——同一台机器、sshfs 挂载、Syncthing 同步、或 NFS。在这个假设下做到极致简单。

---

## 三、核心架构

### 3.1 身份层

```
每个 agent 初始化时生成：
  Ed25519 密钥对
  agent_id = base58(sha256(pubkey)[:16])   ← 全球唯一，自生成，无需注册

身份文件：~/.agent-post/identities/{agent_id}.json
{
  "agent_id": "3kQ7mWxP9nL2vR5s",
  "name": "昼殿",
  "group": "圣殿",
  "pubkey": "base58...",
  "created": "2026-06-11T00:00:00Z"
}
```

- **身份 = 公钥哈希**，对标 Bitcoin 地址模型
- **自生成、自拥有**，不需要 CA、DNS、账本
- **签名 = 防伪**，每条消息带 Ed25519 签名

### 3.2 寻址层

```
单播：  to: "agent_id"          → 投递到指定 agent 的 inbox
组播：  to: "group:圣殿"        → 投递到组内所有 agent 的 inbox
广播：  to: "*"                 → 投递到所有已知 agent 的 inbox
```

组播的关键：同一组的 agent 共享文件系统，消息只需写入组目录，每个 agent 轮询自己的 inbox。

```
~/.agent-post/
  groups/
    圣殿/
      inboxes/
        3kQ7mWxP9nL2vR5s/       ← 昼殿的独立信箱
        7tY4nB8sD2cF6gH1/       ← 月殿的独立信箱
        9zX2pM5vL8wQ3rJ6/       ← 星殿的独立信箱

    开发/
      inboxes/
        1aB3cD5eF7gH9iJ2/
        ...
```

### 3.3 消息格式

每条消息是一个 JSONL 行（append-only）：

```json
{
  "id": "a1b2c3d4",
  "from": "3kQ7mWxP9nL2vR5s",
  "to": "7tY4nB8sD2cF6gH1",
  "type": "text",
  "content": "服务器今天跑了 xxx",
  "refs": [],
  "ts": "2026-06-11T12:00:00Z",
  "sig": "base58-ed25519-signature"
}
```

消息类型：
```
text       — 纯文本消息
file_ref   — 文件引用（refs 含路径，文件本体在共享 files/ 目录）
broadcast  — 广播消息
system     — 系统通知（加入/离开/心跳）
```

签名过程：
```
1. 序列化消息（排除 sig 字段）为规范化 JSON（RFC 8785）
2. SHA-256 哈希
3. Ed25519 签名
4. base58 编码后填入 sig 字段
```

### 3.4 传输层

**组内 = 文件 inbox（零依赖）**

```
发送：append JSONL → ~/.agent-post/groups/{group}/inboxes/{to}/
接收：轮询自己的 inbox 目录 → 读新 JSONL 行 → 验签 → 处理
```

```
Agent A 发送消息到 Agent B（同一组）：

  A: fs.append("groups/圣殿/inboxes/B/mailbox.jsonl", signed_msg)
  
  B: (定期或启动时)
     for msg in read_new_lines("groups/圣殿/inboxes/B/mailbox.jsonl"):
       if verify_signature(msg, A.pubkey):
         process(msg)
       record_watermark(msg.id)
```

**跨组 = SSE relay**

```
组 A 的 relay 进程：
  监 listener 本组 inbox → 有跨组消息 → push SSE → 组 B 的 relay
  
组 B 的 relay 进程：
  收到 SSE push → 写入本组 inbox → 目标 agent 轮询发现
```

---

## 四、与 Sage 的关系

Agent Post 是独立项目，Sage 是它的一个客户端。

```
Sage v0.5.1+
  └─ 集成 Agent Post client
       ├─ 启动时读身份 → 知道自己是谁
       ├─ 轮询 inbox → 收到消息
       ├─ 工具调用 → 发送消息
       └─ 文件 inbox → 替代纯内存 AgentBus
```

Sage 内部不再维护 agent 身份和通信逻辑，全部委托给 Agent Post。AgentBus 升级为 AgentPostBus——内存层保留，文件层由 Agent Post 提供。

---

## 五、与现有方案的对比

| 维度 | MCP | A2A | SAMP | OpenFused | **Agent Post** |
|------|-----|-----|------|-----------|----------------|
| 通信模式 | 请求-响应 | 任务委派 | 文件追加 | 文件追加 | 文件追加 |
| 身份 | OAuth 2.1 | OAuth+JWS | alias | Ed25519 | Ed25519 |
| 分组 | 无 | 无 | 无 | keyring | 组目录 |
| 跨机器 | SSE/HTTP | HTTP | 文件同步 | 文件同步 | 文件+SSE relay |
| 依赖 | SDK | HTTP+JSON | 无 | 无 | 无 |
| 离线 | 否 | 否 | 是 | 是 | 是 |

---

## 六、实施阶段

### Phase 1：核心协议（文件 inbox + 身份 + 签名）

- `agent-post init` — 生成密钥对 + 身份文件
- `agent-post identity` — 查看/导出身份信息
- `agent-post send` — 签名并追加消息到目标 inbox
- `agent-post poll` — 轮询自己的 inbox，验证签名，输出新消息
- `agent-post groups` — 管理组目录

### Phase 2：MCP server 包装

- 将 Phase 1 的功能包装为 MCP server
- 任何 MCP 客户端可通过工具调用使用 Agent Post
- Sage 通过 `McpClient` 连接

### Phase 3：跨组 relay

- SSE relay 进程（组间桥接）
- Relay 发现（组内自动发现 relay 端点）

### Phase 4：SDK + 集成

- TypeScript SDK
- Sage 内置集成（AgentPostBus 替代 AgentBus）
- 文档 + 示例

---

## 七、参考来源

### 直接参考

- **CC 文件 inbox**：`~/.claude/teams/{team}/inboxes/{name}.json` + JSONL 追加 + 文件锁 + 1s 轮询
- **三姐妹邮箱**：`shared-memory/mailbox.md` 追加写入 + sshfs 跨机器
- **OpenFused**：Ed25519 + age 加密 + inbox/outbox 目录结构
- **SAMP**：JSONL + SHA-256 内容寻址 + watermark 消费
- **fleet-i2i**：四种路由模式（unicast/multicast/anycast/broadcast）
- **AEX**：四种 DID 方法 + Ed25519 签名 + 规范化序列化
- **agentic-identity**：Ed25519 密钥对 + `.aid` 文件 + 签名回执

### 概念参考

- **Bitcoin 地址模型**：身份 = 公钥哈希，自生成，无需注册
- **Email 的异步性**：发后即忘，收件轮询
- **Nostr**：npub 身份 + relay 网络 + inbox/outbox 分离
- **Plan 9 "一切皆文件"**：文件系统即协议
