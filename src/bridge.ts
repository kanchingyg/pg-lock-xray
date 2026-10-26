import { createHash } from "node:crypto";

import { assertLoopbackLlmBaseUrl } from "./sql-path.js";

/** Constant `DEFAULT_N_CTX` defining default n ctx. */
export const DEFAULT_N_CTX = 4096;
const TRUNC_MARKER = "[…truncated by pg-lock-xray…]";

/** Configuration and data shape for `McpToolAnnotations` (mcp tool annotations). */
export type McpToolAnnotations = {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
};

/** Configuration and data shape for `McpToolDefinition` (mcp tool definition). */
export type McpToolDefinition<TArgs = Record<string, unknown>, TResult = unknown> = {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  };
  annotations?: McpToolAnnotations;
  mutates?: boolean;
  handler: (
    args: TArgs,
    ctx: { dryRun: boolean; allowWrite: boolean; nCtx: number },
  ) => Promise<TResult> | TResult;
};

/** Configuration and data shape for `GuardOptions` (guard options). */
export type GuardOptions = { allowWrite?: boolean; dryRun?: boolean };

let allowWrite = false;
let dryRun = false;
let nCtx = DEFAULT_N_CTX;

/** Executes `setGuards` to set guards in `pg-lock-xray`. */
export function setGuards(opts: GuardOptions): void {
  allowWrite = Boolean(opts.allowWrite);
  dryRun = Boolean(opts.dryRun);
}

/** Executes `setNCtx` to set nctx in `pg-lock-xray`. */
export function setNCtx(value: number): void {
  nCtx = value > 0 ? value : DEFAULT_N_CTX;
}

/** Executes `headTailTruncate` to head tail truncate in `pg-lock-xray`. */
export function headTailTruncate(text: string, maxChars: number): string {
  if (text.length <= maxChars) return text;
  const headLen = Math.floor(maxChars * 0.6);
  const tailLen = Math.max(0, Math.floor(maxChars * 0.4) - TRUNC_MARKER.length);
  return text.slice(0, headLen) + TRUNC_MARKER + text.slice(-tailLen);
}

/** Executes `canonicalizeJson` to canonicalize json in `pg-lock-xray`. */
export function canonicalizeJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalizeJson(v)).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`).join(",")}}`;
}

const loopState = { lastHash: "", repeatCount: 0 };

/** Executes `resetLoopBreaker` to reset loop breaker in `pg-lock-xray`. */
export function resetLoopBreaker(): void {
  loopState.lastHash = "";
  loopState.repeatCount = 0;
}

/** Executes `checkLoopBreaker` to check loop breaker in `pg-lock-xray`. */
export function checkLoopBreaker(toolName: string, args: unknown): string | null {
  const h = createHash("sha256")
    .update(`${toolName}:${canonicalizeJson(args)}`)
    .digest("hex");
  if (h === loopState.lastHash) loopState.repeatCount++;
  else {
    loopState.lastHash = h;
    loopState.repeatCount = 1;
  }
  if (loopState.repeatCount >= 3) {
    return "LOOP_BREAKER: Identical tool call repeated 2 times consecutively. Stop calling tools and return your final synthesis.";
  }
  return null;
}

/** Executes `isMutatingMcpTool` to is mutating mcp tool in `pg-lock-xray`. */
export function isMutatingMcpTool(
  tool: { mutates?: boolean; annotations?: { destructiveHint?: boolean } } | null | undefined,
): boolean {
  return Boolean(tool?.mutates || tool?.annotations?.destructiveHint);
}

/** Executes `guardMutatingTool` to guard mutating tool in `pg-lock-xray`. */
export function guardMutatingTool(
  tool: { mutates?: boolean; annotations?: { destructiveHint?: boolean } } | null | undefined,
): { blocked: boolean; reason?: string } {
  if (!isMutatingMcpTool(tool)) return { blocked: false };
  if (dryRun) return { blocked: false };
  if (!allowWrite) {
    return { blocked: true, reason: "Read-only mode: pass --allow-write to enable mutating tools." };
  }
  return { blocked: false };
}

const WIN_DRIVE_RE = /^([A-Za-z]):\\(.*)$/;
const WSL_RE = /^\/mnt\/([a-z])\/(.*)$/i;
const SECRET_RE =
  /(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|Bearer\s+[a-zA-Z0-9._-]+)/g;

/** Executes `windowsToWsl` to windows to wsl in `pg-lock-xray`. */
export function windowsToWsl(p: string): string {
  const m = p.match(WIN_DRIVE_RE);
  if (!m) return p;
  return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, "/")}`;
}

/** Executes `wslToWindows` to wsl to windows in `pg-lock-xray`. */
export function wslToWindows(p: string): string {
  const m = p.match(WSL_RE);
  if (!m) return p;
  return `${m[1].toUpperCase()}:\\${m[2].replace(/\//g, "\\")}`;
}

/** Executes `normalizePathsDeep` to normalize paths deep in `pg-lock-xray`. */
export function normalizePathsDeep<T>(value: T, toWsl: boolean): T {
  if (typeof value === "string") {
    if (toWsl && WIN_DRIVE_RE.test(value)) return windowsToWsl(value) as T;
    if (!toWsl && WSL_RE.test(value)) return wslToWindows(value) as T;
    return value;
  }
  if (Array.isArray(value)) return value.map((v) => normalizePathsDeep(v, toWsl)) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = normalizePathsDeep(v, toWsl);
    }
    return out as T;
  }
  return value;
}

/** Executes `redactSecrets` to redact secrets in `pg-lock-xray`. */
export function redactSecrets(text: string): string {
  return text.replace(SECRET_RE, "[REDACTED]");
}

let stdoutHijacked = false;
let jsonRpcWrite: ((line: string) => void) | null = null;

/** Constant `jsonRpcFrameLog` defining json rpc frame log. */
export const jsonRpcFrameLog: string[] = [];

/** Executes `hijackStdoutForMcp` to hijack stdout for mcp in `pg-lock-xray`. */
export function hijackStdoutForMcp(): void {
  if (stdoutHijacked) return;
  stdoutHijacked = true;
  const native = process.stdout.write.bind(process.stdout);
  jsonRpcWrite = (line: string) => native(line);
  process.stdout.write = ((chunk: unknown, ...args: unknown[]) => {
    const str = typeof chunk === "string" ? chunk : Buffer.from(chunk as Buffer).toString();
    if (str.trim().startsWith("{") && str.includes('"jsonrpc"')) {
      return native(chunk as string, ...(args as []));
    }
    process.stderr.write(str);
    return true;
  }) as typeof process.stdout.write;
}

/** Executes `writeJsonRpcFrame` to write json rpc frame in `pg-lock-xray`. */
export function writeJsonRpcFrame(obj: object): void {
  const line = JSON.stringify(obj) + "\n";
  jsonRpcFrameLog.push(line);
  if (jsonRpcWrite) jsonRpcWrite(line);
  else process.stdout.write(line);
}

/** Configuration and data shape for `NCtxSource` (nctx source). */
export type NCtxSource = "llama.cpp" | "ollama" | "vllm" | "fallback";

/** Executes `probeNCtx` to probe nctx in `pg-lock-xray`. */
export async function probeNCtx(
  baseUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<{ nCtx: number; source: NCtxSource }> {
  const base = baseUrl.replace(/\/$/, "");
  try {
    const props = await fetchImpl(`${base}/props`);
    if (props.ok) {
      const j = (await props.json()) as { n_ctx?: number };
      if (j.n_ctx && j.n_ctx > 0) return { nCtx: j.n_ctx, source: "llama.cpp" };
    }
  } catch {
    /* continue */
  }
  try {
    const show = await fetchImpl(`${base}/api/show`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "dummy" }),
    });
    if (show.ok) {
      const j = (await show.json()) as { model_info?: Record<string, unknown> };
      for (const [k, v] of Object.entries(j.model_info ?? {})) {
        if (k.includes("context_length") && typeof v === "number" && v > 0) {
          return { nCtx: v, source: "ollama" };
        }
      }
    }
  } catch {
    /* continue */
  }
  try {
    const models = await fetchImpl(`${base}/v1/models`);
    if (models.ok) {
      const j = (await models.json()) as { data?: Array<{ max_model_len?: number }> };
      const len = j.data?.[0]?.max_model_len;
      if (len && len > 0) return { nCtx: len, source: "vllm" };
    }
  } catch {
    /* continue */
  }
  return { nCtx: DEFAULT_N_CTX, source: "fallback" };
}

const THINKING_BLOCK_RE =
  /<(?:redacted_thinking|think)>[\s\S]*?<\/(?:redacted_thinking|think)>/gi;

/** Executes `stripRedactedThinking` to strip redacted thinking in `pg-lock-xray`. */
export function stripRedactedThinking(text: string): string {
  return text.replace(THINKING_BLOCK_RE, "").trim();
}

/** Configuration and data shape for `ReasoningState` (reasoning state). */
export type ReasoningState = { inToolLoop: boolean };

/** Executes `createReasoningState` to create reasoning state in `pg-lock-xray`. */
export function createReasoningState(): ReasoningState {
  return { inToolLoop: false };
}

/** Executes `applyReasoningContentPolicy` to apply reasoning content policy in `pg-lock-xray`. */
export function applyReasoningContentPolicy(
  messages: Array<Record<string, unknown>>,
  state: ReasoningState,
  newUserTurn: boolean,
): Array<Record<string, unknown>> {
  if (newUserTurn) state.inToolLoop = false;
  return messages.map((m) => {
    const out = { ...m };
    if (newUserTurn && m.role === "assistant") delete out.reasoning_content;
    if (Array.isArray(m.tool_calls) && m.tool_calls.length) state.inToolLoop = true;
    return out;
  });
}

/** Configuration and data shape for `ProviderId` (provider id). */
export type ProviderId =
  | "deepseek"
  | "dashscope"
  | "moonshot"
  | "ollama"
  | "openai"
  | "generic";

/** Executes `detectProvider` to detect provider in `pg-lock-xray`. */
export function detectProvider(baseUrl: string): ProviderId {
  const u = baseUrl.toLowerCase();
  if (u.includes("deepseek")) return "deepseek";
  if (u.includes("dashscope")) return "dashscope";
  if (u.includes("moonshot")) return "moonshot";
  if (u.includes("11434") || u.includes("ollama")) return "ollama";
  if (u.includes("openai")) return "openai";
  return "generic";
}

/** Executes `normalizeToolChoice` to normalize tool choice in `pg-lock-xray`. */
export function normalizeToolChoice(toolChoice: unknown, provider: ProviderId): unknown {
  if (toolChoice === "required" && (provider === "dashscope" || provider === "moonshot")) {
    return "auto";
  }
  return toolChoice;
}

/** Executes `sanitizeRequestBody` to sanitize request body in `pg-lock-xray`. */
export function sanitizeRequestBody(
  body: Record<string, unknown>,
  reasoner: boolean,
): Record<string, unknown> {
  const out = { ...body };
  if (reasoner) {
    delete out.temperature;
    delete out.top_p;
  }
  return out;
}

/** Executes `buildRecencyAnchor` to build recency anchor in `pg-lock-xray`. */
export function buildRecencyAnchor(sigs: Array<{ name: string; summary: string }>): string {
  const lines = sigs.map((s) => `- ${s.name}: ${s.summary}`);
  return [
    "[AVAILABLE TOOLS — ANCHORED FOR RECENCY]",
    ...lines,
    'To call a tool, output ONLY: <tool_call>{"name": "TOOL_NAME", "arguments": {...}}</tool_call>',
  ].join("\n");
}

/** Executes `anchorPromptTail` to anchor prompt tail in `pg-lock-xray`. */
export function anchorPromptTail(prompt: string, anchor: string): string {
  const marker = "\nASSISTANT:";
  const idx = prompt.lastIndexOf(marker);
  if (idx === -1) return `${prompt}\n\n${anchor}\n${marker}`;
  return `${prompt.slice(0, idx)}\n\n${anchor}\n${prompt.slice(idx)}`;
}

/** Stateful helper class `StreamToolJsonAbort` (stream tool json abort). */
export class StreamToolJsonAbort {
  private depth = 0;
  private started = false;
  private acc = "";

  /** Member `feed` (feed). */
  feed(chunk: string): boolean {
    this.acc += chunk;
    if (!this.started) {
      if (
        /<tool_call>/i.test(this.acc) ||
        /✿FUNCTION✿/i.test(this.acc) ||
        /"name"\s*:\s*"/.test(this.acc)
      ) {
        this.started = true;
      }
    }
    this.depth = braceDepth(this.acc);
    return this.started && this.depth === 0 && /\{[\s\S]*\}/.test(this.acc);
  }
}

function braceDepth(text: string): number {
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (escape) {
      escape = false;
      continue;
    }
    if (inString) {
      if (c === "\\") escape = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}") depth--;
  }
  return depth;
}

/** Executes `parseDirtyToolCall` to parse dirty tool call in `pg-lock-xray`. */
export function parseDirtyToolCall(
  rawOutput: string,
  tools: McpToolDefinition[],
): { name: string; arguments: Record<string, unknown> } | null {
  const text = stripRedactedThinking(rawOutput);
  const names = new Set(tools.map((t) => t.name));

  const hermes = text.match(/<tool_call>\s*(\{[\s\S]*?\})\s*<\/tool_call>/i);
  if (hermes) {
    try {
      const obj = JSON.parse(hermes[1]) as { name?: string; arguments?: Record<string, unknown> };
      if (obj.name && names.has(obj.name)) {
        return { name: obj.name, arguments: obj.arguments ?? {} };
      }
    } catch {
      /* continue */
    }
  }

  const qwen = text.match(/✿FUNCTION✿:\s*([^\n]+)\s*✿ARGS✿:\s*([\s\S]*?)(?:✿RESULT✿|$)/i);
  if (qwen) {
    const name = qwen[1].trim();
    if (names.has(name)) {
      try {
        const args = JSON.parse(qwen[2].replace(/'/g, '"')) as Record<string, unknown>;
        return { name, arguments: args };
      } catch {
        return { name, arguments: {} };
      }
    }
  }

  const iq = text.match(/\{\s*['"]?cmd['"]?\s*:\s*['"]([^'"]+)['"]/);
  if (iq) return { name: "run_shell", arguments: { cmd: iq[1] } };

  return null;
}

/** Executes `l2Normalize` to l2 normalize in `pg-lock-xray`. */
export function l2Normalize(vec: number[]): number[] {
  let sum = 0;
  for (const v of vec) sum += v * v;
  const norm = Math.sqrt(sum) || 1;
  return vec.map((v) => v / norm);
}

/** Executes `mrlSlice` to mrl slice in `pg-lock-xray`. */
export function mrlSlice(vec: number[], dimensions: number): number[] {
  return l2Normalize(vec.slice(0, dimensions));
}

/** Executes `chunkArray` to chunk array in `pg-lock-xray`. */
export function chunkArray<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

/** Executes `normalizeEmbedBatch` to normalize embed batch in `pg-lock-xray`. */
export async function normalizeEmbedBatch(
  inputs: string[],
  options: {
    dimensions?: number;
    maxBatch: number;
    embed: (batch: string[], dimensions?: number) => Promise<number[][]>;
  },
): Promise<number[][]> {
  const nonEmpty = inputs.map((t, i) => ({ t, i })).filter((x) => x.t.trim().length > 0);
  const batches = chunkArray(nonEmpty, options.maxBatch);
  const vectors = new Map<number, number[]>();
  for (const batch of batches) {
    const texts = batch.map((b) => b.t);
    const got = await options.embed(texts, options.dimensions);
    for (let j = 0; j < batch.length; j++) {
      let vec = got[j] ?? [];
      if (options.dimensions && vec.length >= options.dimensions) {
        vec = mrlSlice(vec, options.dimensions);
      }
      vectors.set(batch[j].i, vec);
    }
  }
  const dim = options.dimensions ?? vectors.values().next().value?.length ?? 0;
  return inputs.map((_, i) => vectors.get(i) ?? new Array(dim).fill(0));
}

/** Executes `normalizeEmbeddingsRequest` to normalize embeddings request in `pg-lock-xray`. */
export async function normalizeEmbeddingsRequest(
  req: Record<string, unknown>,
  provider: string,
): Promise<{ data: Array<{ embedding: number[] | string; index: number }>; model: string }> {
  const input = Array.isArray(req.input) ? req.input : req.input ? [req.input] : [];
  const dim =
    typeof req.dimensions === "number"
      ? req.dimensions
      : provider === "ollama"
        ? 768
        : 1024;
  const lockDim = typeof req.lockDimension === "number" ? req.lockDimension : undefined;
  if (lockDim !== undefined && lockDim !== dim) {
    throw new Error(`Dimension fingerprint mismatch: lock expects ${lockDim}, got ${dim}`);
  }
  const strings = input.map((x) => String(x));
  const data = strings.map((_, index) => ({
    index,
    embedding: new Array(dim).fill(0),
  }));
  return { data, model: String(req.model ?? "local") };
}

/** Executes `callOpenAiCompatChat` to call open ai compat chat in `pg-lock-xray`. */
export async function callOpenAiCompatChat(
  baseUrl: string,
  body: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  assertLoopbackLlmBaseUrl(baseUrl);
  const url = `${baseUrl.replace(/\/$/, "")}/v1/chat/completions`;
  const model = String(body.model ?? "local");
  const sanitized = sanitizeRequestBody(body, /reasoner|thinking/i.test(model));
  const res = await fetchImpl(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(sanitized),
  });
  const j = (await res.json()) as {
    choices?: Array<{ message?: { content?: string; reasoning_content?: string } }>;
  };
  const msg = j.choices?.[0]?.message;
  const raw = msg?.content ?? msg?.reasoning_content ?? "";
  return stripRedactedThinking(raw);
}

/** Configuration and data shape for `McpServerOptions` (mcp server options). */
export type McpServerOptions = {
  tools: McpToolDefinition[];
  pathToWsl?: boolean;
  serverName?: string;
  version?: string;
};

/** Executes `startMcpServer` to start mcp server in `pg-lock-xray`. */
export function startMcpServer(
  meta: { name: string; version: string },
  tools: McpToolDefinition[],
  options?: { allowWrite?: boolean; pathToWsl?: boolean },
): void {
  hijackStdoutForMcp();
  if (options?.allowWrite) setGuards({ allowWrite: true });
  const toWsl = options?.pathToWsl ?? process.env.PG_LOCK_XRAY_PATH_WSL === "1";
  const handlers = new Map(tools.map((t) => [t.name, t]));
  let buffer = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    buffer += chunk;
    let idx: number;
    while ((idx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line) as {
          jsonrpc?: string;
          id?: number | string;
          method?: string;
          params?: Record<string, unknown>;
        };
        dispatchMcpMessage(msg, {
          tools,
          handlers,
          toWsl,
          serverName: meta.name,
          version: meta.version,
        });
      } catch {
        /* ignore */
      }
    }
  });
}

/** Configuration and data shape for `DispatchCtx` (dispatch ctx). */
export type DispatchCtx = {
  tools: McpToolDefinition[];
  handlers: Map<string, McpToolDefinition>;
  toWsl: boolean;
  serverName: string;
  version: string;
};

/** Executes `dispatchMcpMessage` to dispatch mcp message in `pg-lock-xray`. */
export function dispatchMcpMessage(
  msg: {
    jsonrpc?: string;
    id?: number | string;
    method?: string;
    params?: Record<string, unknown>;
  },
  ctx: DispatchCtx,
): void {
  const { id, method, params } = msg;
  if (method === "initialize") {
    writeJsonRpcFrame({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: ctx.serverName, version: ctx.version },
      },
    });
    return;
  }
  if (method === "notifications/initialized") return;
  if (method === "tools/list") {
    writeJsonRpcFrame({
      jsonrpc: "2.0",
      id,
      result: {
        tools: ctx.tools.map((t) => ({
          name: t.name,
          description: t.description,
          inputSchema: t.inputSchema,
          annotations: t.annotations,
        })),
      },
    });
    return;
  }
  if (method === "tools/call") {
    const name = params?.name as string;
    const args = normalizePathsDeep(
      (params?.arguments as Record<string, unknown>) ?? {},
      ctx.toWsl,
    );
    const loopErr = checkLoopBreaker(name, args);
    if (loopErr) {
      writeJsonRpcFrame({
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: loopErr }], isError: true },
      });
      return;
    }
    const tool = ctx.handlers.get(name);
    const guard = guardMutatingTool(tool);
    if (guard.blocked) {
      writeJsonRpcFrame({
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: guard.reason ?? "blocked" }], isError: true },
      });
      return;
    }
    void (async () => {
      try {
        const result = tool
          ? await tool.handler(args, { dryRun, allowWrite, nCtx })
          : { error: "unknown tool" };
        let text = redactSecrets(
          typeof result === "string" ? result : JSON.stringify(result, null, 2),
        );
        text = headTailTruncate(text, Math.floor(nCtx * 4 * 0.3));
        text = normalizePathsDeep(text, !ctx.toWsl) as string;
        writeJsonRpcFrame({
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text }] },
        });
      } catch (e) {
        writeJsonRpcFrame({
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: String(e) }], isError: true },
        });
      }
    })();
    return;
  }
  if (id !== undefined) {
    writeJsonRpcFrame({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Method not found: ${method}` },
    });
  }
}
