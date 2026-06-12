import { spawn, ChildProcess } from "child_process";
import { createInterface } from "readline";
import type {
  Identity,
  IdentityExport,
  PostMessage,
  GroupInfo,
  PairInvite,
  SendResult,
  AgentPostOptions,
} from "./types";

export * from "./types";

type JsonRpcId = string | number;

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: JsonRpcId;
  method: string;
  params: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result?: unknown;
  error?: { code: number; message: string };
}

export class AgentPostClient {
  private binaryPath: string;
  private identitiesDir?: string;
  private groupsDir?: string;
  private process: ChildProcess | null = null;
  private requestId = 0;
  private pending = new Map<JsonRpcId, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private initialized = false;

  constructor(options: AgentPostOptions = {}) {
    this.binaryPath = options.binaryPath ?? "agent-post";
    this.identitiesDir = options.identitiesDir;
    this.groupsDir = options.groupsDir;
  }

  private async connect(): Promise<void> {
    if (this.process) return;

    const args = ["mcp"];
    if (this.identitiesDir) args.push("--identities-dir", this.identitiesDir);
    if (this.groupsDir) args.push("--groups-dir", this.groupsDir);

    this.process = spawn(this.binaryPath, args, {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const rl = createInterface({ input: this.process.stdout! });
    rl.on("line", (line: string) => {
      try {
        const resp: JsonRpcResponse = JSON.parse(line);
        const pending = this.pending.get(resp.id);
        if (pending) {
          this.pending.delete(resp.id);
          if (resp.error) {
            pending.reject(new Error(resp.error.message));
          } else {
            pending.resolve(resp.result);
          }
        }
      } catch {
        // ignore parse errors on non-JSON lines
      }
    });

    this.process.stderr?.on("data", (data: Buffer) => {
      // stderr is used for logging, not errors
    });

    this.process.on("exit", () => {
      this.process = null;
      this.initialized = false;
    });

    // Initialize MCP connection
    await this.call("initialize", {});
    this.initialized = true;
  }

  private call(method: string, params: Record<string, unknown>): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      const req: JsonRpcRequest = { jsonrpc: "2.0", id, method, params };
      this.pending.set(id, { resolve, reject });

      if (!this.process?.stdin) {
        reject(new Error("MCP process not connected"));
        return;
      }
      this.process.stdin.write(JSON.stringify(req) + "\n");
    });
  }

  private async ensureConnected(): Promise<void> {
    if (!this.initialized) await this.connect();
  }

  // ── Tool methods ──

  /** Initialize a new identity */
  async init(params: {
    name: string;
    group?: string;
    passphrase?: string;
  }): Promise<{ agent_id: string; name: string; group: string }> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "init",
      arguments: {
        name: params.name,
        group: params.group ?? "default",
        passphrase: params.passphrase ?? "",
      },
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** Show current identity */
  async identityShow(): Promise<Identity> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "identity_show",
      arguments: {},
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** List all identities */
  async identityList(): Promise<IdentityExport[]> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "identity_list",
      arguments: {},
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** Send a pairing invitation */
  async pairInvite(params: {
    to: string;
    group: string;
    recovery?: boolean;
  }): Promise<{ nonce: string; status: string }> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "pair_invite",
      arguments: params,
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** Check pending invitations */
  async pairCheck(group: string): Promise<PairInvite[]> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "pair_check",
      arguments: { group },
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** Accept a pairing invitation */
  async pairAccept(nonce: string, group: string): Promise<{ nonce: string; status: string }> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "pair_accept",
      arguments: { nonce, group },
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** Reject a pairing invitation */
  async pairReject(
    nonce: string,
    group: string,
    reason?: string,
  ): Promise<{ status: string }> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "pair_reject",
      arguments: { nonce, group, reason },
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** Confirm a pairing */
  async pairConfirm(nonce: string, group: string): Promise<{ status: string }> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "pair_confirm",
      arguments: { nonce, group },
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** Send a message */
  async send(params: {
    to: string;
    content: string;
    msg_type?: "text" | "system" | "file_ref";
  }): Promise<SendResult> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "send_message",
      arguments: {
        to: params.to,
        content: params.content,
        msg_type: params.msg_type ?? "text",
      },
    }) as { content: { text: string }[] };
    const parsed = JSON.parse(result.content[0].text);
    if (parsed.Error) throw new Error(parsed.Error);
    return parsed;
  }

  /** Poll inbox for new messages */
  async poll(group?: string): Promise<PostMessage[]> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "poll_inbox",
      arguments: group ? { group } : {},
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** Create a group */
  async groupCreate(name: string): Promise<{ group: string; status: string }> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "group_create",
      arguments: { name },
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** List all groups */
  async groupList(): Promise<string[]> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "group_list",
      arguments: {},
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** Show group details */
  async groupInfo(name: string): Promise<GroupInfo> {
    await this.ensureConnected();
    const result = await this.call("tools/call", {
      name: "group_info",
      arguments: { name },
    }) as { content: { text: string }[] };
    return JSON.parse(result.content[0].text);
  }

  /** Disconnect and clean up */
  async close(): Promise<void> {
    if (this.process) {
      this.process.kill();
      this.process = null;
      this.initialized = false;
    }
    this.pending.clear();
  }
}
