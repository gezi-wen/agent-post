/** Agent Post TypeScript type definitions */

export interface Identity {
  agent_id: string;
  name: string;
  group: string;
  pubkey: string;
  created: string;
}

export interface IdentityExport {
  agent_id: string;
  name: string;
  group: string;
  pubkey: string;
  created: string;
}

export type MessageType = "text" | "system" | "file_ref";

export interface PostMessage {
  id: string;
  from: string;
  to: string;
  type: MessageType;
  content: string;
  refs: string[];
  ts: string;
  sig: string;
}

export interface Member {
  agent_id: string;
  name: string;
  pubkey: string;
  joined: string;
}

export interface GroupInfo {
  group: string;
  member_count: number;
  members: Member[];
}

export interface PairInvite {
  from_id: string;
  group_name: string;
  nonce: string;
  expires_at: string;
  recovery?: boolean;
}

export interface SendResult {
  id: string;
  delivered_to: string[];
}

export interface AgentPostOptions {
  /** Path to agent-post binary. Default: "agent-post" */
  binaryPath?: string;
  /** Custom identities directory */
  identitiesDir?: string;
  /** Custom groups directory */
  groupsDir?: string;
}
