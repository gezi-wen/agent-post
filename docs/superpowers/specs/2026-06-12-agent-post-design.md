# Agent Post — 设计规格书

**日期：2026-06-12 · 昼殿**
**状态：设计完成，待转入实施**

---

## 一、定位

Agent Post 是 AI agent 的身份+通信协议。核心理念三合一：文件 inbox + Ed25519 身份 + 分组路由。

一句话：**Email 的异步性 + Bitcoin 的去中心化身份 + Signal 的签名可信度，为 AI agent 设计。**

## 二、为什么存在

现有方案的缺口：

| 协议 | 定位 | 缺什么 |
|------|------|--------|
| MCP | agent↔工具 | 不是 agent 间通信协议 |
| A2A | agent↔agent（网络） | 需要 HTTP 端点、DNS、OAuth |
| SAMP | agent↔agent（文件） | 无密码学身份 |
| OpenFused | agent↔agent（文件+加密） | 无分组路由、无配对握手 |
| Parley | agent↔agent（加密） | 无分组路由和组播、无配对握手 |
| agentic-identity | 仅身份 | 不做通信 |

Agent Post 填补的空白：**文件 inbox + 密码学身份 + 分组路由，三者合一。**

## 三、最终形态

```
┌─────────────────────────────────────┐
│ Agent Post Spec（协议规范）          │  ← 产品本体
│ 消息 JSONL 格式 · 签名算法 · 目录布局 │
├─────────────────────────────────────┤
│ agent-post-core（Rust crate）        │  ← 第一参考实现
│ 身份生成 · 消息签名/验签 · inbox 读写 │
├─────────────────────────────────────┤
│ agent-post（CLI 二进制）             │  ← 通用接口
│ init / identity / pair / send / poll │
├─────────────────────────────────────┤
│ agent-post-mcp（MCP server）         │  ← MCP 生态接入
│ CC / Cline / Codex 原生可用          │
├─────────────────────────────────────┤
│ 语言 SDK（TS → Python → ...）       │  ← 深度集成
│ Sage 等应用直接 import              │
└─────────────────────────────────────┘
```

工具链：Rust + cargo-nextest（测试）+ cargo-deny（审计）+ clippy（lint）

---

## 四、身份层

### 4.1 密钥生成

```
Ed25519 密钥对（ed25519-dalek v3）
agent_id = base58(sha256(pubkey)[:16])  ← 16 字节，~12 字符
```

- 自生成、自拥有，无需 CA/注册/DNS
- Bitcoin 地址模型——身份即公钥哈希
- ed25519-dalek v3：ZeroizeOnDrop（内存安全）、verify_strict()（防弱公钥攻击）

### 4.2 身份文件

```
~/.agent-post/identities/{agent_id}.json
{
  "agent_id": "3kQ7mWxP9nL2vR5s",
  "name": "昼殿",
  "group": "圣殿",
  "pubkey": "base58-encoded-32-bytes",
  "secret_key": "base58-encoded-32-bytes",   ← MVP 明文，chmod 600
  "revocation_cert": "预签名吊销证书",
  "created": "2026-06-12T00:00:00Z"
}
```

- 私钥 MVP 明文存，权限 600
- 后续版本加 Argon2id passphrase 加密
- 身份 export 时不带 secret_key

### 4.3 身份缓存

```
~/.agent-post/identities/{其他agent_id}.json
{
  "agent_id": "7tY4nB8sD2cF6gH1",
  "name": "月殿",
  "group": "圣殿",
  "pubkey": "base58-encoded-32-bytes",
  "status": "active" | "revoked"
  "first_seen": "2026-06-12T00:00:00Z"
}
```

- 收到任何 agent 消息后缓存其 pubkey
- 同组 agent 的 pubkey 在 members.toml 中

---

## 五、寻址层

```
单播：to: "agent_id"          → 投递到指定 inbox
组播：to: "group:圣殿"        → 遍历组内 members，逐个投递
广播：to: "*"                 → 遍历所有已知组的 members
```

组播依赖组目录内的 members.toml。

---

## 六、消息格式

### 6.1 JSONL 消息

每条消息一行，append-only：

```json
{
  "id": "a1b2c3d4",
  "from": "3kQ7mWxP9nL2vR5s",
  "to": "7tY4nB8sD2cF6gH1",
  "type": "text",
  "content": "服务器今天跑了 xxx",
  "refs": [],
  "ts": "2026-06-12T12:00:00Z",
  "sig": "base58-ed25519-signature"
}
```

消息类型：`text`、`system`（MVP）。`file_ref` 留待 Phase 2。

消息大小上限：**64KB**。超过走 file_ref（Phase 2）。

### 6.2 签名流程

```
1. 消息对象排除 sig 字段 → 规范化 JSON（RFC 8785 JCS）
2. SHA-256 哈希
3. Ed25519 签名（SigningKey::sign()）
4. base58 编码 → 填入 sig 字段
```

### 6.3 验签流程

```
1. 提取 sig 字段，从消息中移除
2. 剩余字段 → 规范化 JSON（RFC 8785 JCS）
3. SHA-256 哈希
4. VerifyingKey::verify_strict() 验证 sig
   - verify_strict() 拒绝弱公钥
   - JSON 解析失败的行静默跳过（残损消息没有合法签名）
```

---

## 七、传输层

### 7.1 组内投递

```
A → send --to B_id → 查 members.toml → 查 routes.toml → 写 JSONL
```

- 同机：inbox 路径为 groups/{组}/inboxes/{agent_id}/mailbox.jsonl
- 跨机：routes.toml 指定挂载路径，手动配置

### 7.2 接收与去重

```
poll → 读 mailbox.jsonl → 逐行验签 → 比对 watermark → 输出
```

Watermark 格式（`.watermark.json`）：
```json
{
  "3kQ7mWxP9nL2vR5s": {
    "last_ts": "2026-06-12T12:00:00Z",
    "seen_ids": ["a1b2c3d4"]
  }
}
```

去重逻辑同 SAMP：ts < last_ts 跳过；ts == last_ts 且 id in seen_ids 跳过。

### 7.3 并发安全

- JSONL O_APPEND 追加，POSIX 保证小于 PIPE_BUF 的单行写入原子
- 残损行在验签阶段自然过滤
- 不需要文件锁

---

## 八、配置模型

### 8.1 两层结构

**全局 config.toml**（`~/.agent-post/config.toml`）：
```toml
default_identity = "3kQ7mWxP9nL2vR5s"
default_group = "圣殿"

[known_agents]
# 已知 agent 的基本路由信息
```

**组目录**（`~/.agent-post/groups/{组名}/`）：
```
groups/圣殿/
  group.toml      ← 组元信息 + 权限策略
  members.toml    ← 组成员（配对确认后写入）
  routes.toml     ← 跨机 inbox 路径映射
  pending/        ← 配对握手临时文件
  revocations/    ← 吊销证书
  inboxes/
    {agent_id}/
      mailbox.jsonl
      .watermark.json
```

- 全局声明「我是谁」，组绑定「我和谁在同一个频道」
- routes.toml 手动配置，无自动发现

---

## 九、配对协议

### 9.1 三次握手

```
① invite：   A → 共享信道 → B
   A 签名：{A_id, B_id, 组名, nonce, 过期=3天}

② accept：   B → 共享信道 → A
   B 签名：{①的hash, B_id, A_id, 组名, accept|reject, [reason]}

③ confirm：  A → 共享信道 → B
   A 签名：{②的hash}
```

- 共享信道：同机 = 组内 pending/ 目录，跨机 = 挂载或手动复制（跨机 MVP 不覆盖）
- ① 带 nonce + 过期时间防重放
- ② reject 时带 reason，通知 A
- ③ 防止 ② 被截获重放到其他上下文
- ③ 完成后双方写入 members.toml，清理 pending 文件

### 9.2 防攻击

| 攻击 | 防御 |
|------|------|
| C 冒充 A 发 invite | 验签：没有 A 的 Ed25519 签名 → 丢弃 |
| C 截获 invite 重放 | invite 带 to: B_id，C 的 id 不匹配 |
| B 接受后 A 不承认 | ② 有 B 的签名，不可否认 |
| C 把旧 accept 重放 | ③ A 签的是 ② 的 hash，旧 hash 对不上 |
| 单方面被拉进组 | 没有 ② accept，A 单方面写 members.toml 无效 |

---

## 十、密钥吊销与恢复

### 10.1 吊销

```
agent-post key revoke [--reason "..."]
```

- 使用创建身份时预签名的 revocation_certificate
- 写入 groups/{组}/revocations/{agent_id}.json
- 任何 agent 下次 poll 时读到 → 标记该 pubkey 为 revoked → 不再验签通过

### 10.2 恢复

```
agent-post init          ← 生成新身份
agent-post pair invite --to B --group 圣殿 --recovery
                         ← B 的终端显示安全数字

安全数字 = sha256(旧pubkey + 新pubkey) 的前 10 位十进制

B 向 昼殿 口头确认数字匹配 → pair accept → 配对完成
```

- 不设定期轮换（离线 agent 会错过，文件 inbox 不适合）
- 不设恢复码（最终信任锚点是安全数字，恢复码多此一举）
- 不设机器指纹（换机/重装/Docker 全崩，挡不住同机 attacker）
- 信任重建的唯一锚点：Signal 式安全数字验证

---

## 十一、CLI 命令（Phase 1）

```
agent-post init
  生成密钥对 + 身份文件 + 预签名吊销证书
  输出 agent_id

agent-post identity show|list|export [agent_id]
  查看/列出/导出身份

agent-post pair invite --to <id> --group <组> [--name <名称>] [--recovery]
  发起配对。--recovery 用于密钥恢复场景，显示安全数字供对方验证
agent-post pair check
  列出本组的 pending invite
agent-post pair accept <invite_id>
  接受配对
agent-post pair reject <invite_id> [--reason "..."]
  拒绝配对
agent-post pair confirm <accept_id>
  确认接受

agent-post send --to <id|group:名称|*> --type <text|system> --content "..."
  签名并投递消息

agent-post poll [--group <组>] [--follow]
  轮询 inbox，验签输出新消息

agent-post key revoke [--reason "..."]
  吊销当前密钥

agent-post group create|list|info <组名>
  组管理
agent-post group add-route --agent <id> --path <路径>
  手动添加跨机 inbox 路由
```

---

## 十二、Phase 1 范围

**包含**：身份生成、配对握手、消息收发、组管理、密钥吊销、协议 spec 文档

**不包含**：消息加密（age/X25519）、跨机 relay、MCP server、TS SDK、私钥 passphrase 加密、file_ref、定期轮换

## 十三、Phase 2+ 预留

- **Phase 2**：MCP server + TS SDK + file_ref + 私钥加密
- **Phase 3**：跨组 SSE relay + relay 发现
- **Phase 4**：Python SDK + 文档站 + Sage 内置集成
