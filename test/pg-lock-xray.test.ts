import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  analyzeSqlText,
  analyzeTarget,
  buildFixPreview,
  resolveSqlInput,
} from "../src/sql-analyzer.js";
import {
  assertLoopbackLlmBaseUrl,
  resolveContainedSqlPath,
} from "../src/sql-path.js";
import { rewriteSqlDocument } from "../src/zero-downtime-rewriter.js";
import {
  hijackStdoutForMcp,
  jsonRpcFrameLog,
  dispatchMcpMessage,
  resetLoopBreaker,
  checkLoopBreaker,
  guardMutatingTool,
  setGuards,
  windowsToWsl,
  wslToWindows,
  normalizeEmbedBatch,
  stripRedactedThinking,
  applyReasoningContentPolicy,
  createReasoningState,
  sanitizeRequestBody,
  probeNCtx,
  headTailTruncate,
  buildRecencyAnchor,
  anchorPromptTail,
  StreamToolJsonAbort,
  parseDirtyToolCall,
  normalizeEmbeddingsRequest,
  callOpenAiCompatChat,
  detectProvider,
  normalizeToolChoice,
  type McpToolDefinition,
} from "../src/bridge.js";

const SAMPLE_SQL = `
CREATE INDEX idx_users_email ON users(email);
ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);
`;

describe("sql path containment", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "pg-lock-xray-root-"));
    mkdirSync(join(root, "sql"), { recursive: true });
    writeFileSync(join(root, "sql", "ok.sql"), SAMPLE_SQL);
    writeFileSync(join(root, "package.json"), "{}");
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("accepts allowlisted relative sql paths", () => {
    const resolved = resolveContainedSqlPath("sql/ok.sql", root);
    expect(resolved).toContain("ok.sql");
    const { sql } = resolveSqlInput("sql/ok.sql", root);
    expect(sql).toContain("CREATE INDEX");
  });

  it("rejects path traversal and non-allowlisted paths", () => {
    expect(() => resolveContainedSqlPath("sql/../package.json", root)).toThrow(/traversal/i);
    expect(() => resolveContainedSqlPath("package.json", root)).toThrow(/must be under/i);
    expect(() => resolveContainedSqlPath("/etc/passwd", root)).toThrow(/Absolute/i);
  });

  it("scans allowlisted directories", () => {
    const reports = analyzeTarget("sql", root);
    expect(reports.length).toBe(1);
    expect(reports[0].criticalCount).toBeGreaterThanOrEqual(2);
  });
});

describe("pg-lock-xray analysis", () => {
  it("flags CRITICAL index and FK risks", () => {
    const report = analyzeSqlText(SAMPLE_SQL);
    const critical = report.statements.filter((s) => s.severity === "CRITICAL");
    expect(critical.length).toBeGreaterThanOrEqual(2);
    expect(critical.some((s) => s.risks.includes("index-without-concurrently"))).toBe(true);
    expect(critical.some((s) => s.risks.includes("fk-without-not-valid"))).toBe(true);
  });

  it("rewrites to CONCURRENTLY and NOT VALID + VALIDATE", () => {
    const out = rewriteSqlDocument(SAMPLE_SQL);
    expect(out).toMatch(/CREATE INDEX CONCURRENTLY/i);
    expect(out).toMatch(/NOT VALID/i);
    expect(out).toMatch(/VALIDATE CONSTRAINT fk_user/i);
    const { diff } = buildFixPreview(SAMPLE_SQL);
    expect(diff).toContain("+CREATE INDEX CONCURRENTLY");
  });

  it("scans migration file on disk", () => {
    const dir = mkdtempSync(join(tmpdir(), "pg-lock-xray-"));
    const file = join(dir, "migration.sql");
    writeFileSync(file, SAMPLE_SQL);
    const report = analyzeSqlText(SAMPLE_SQL, file);
    expect(report.criticalCount).toBeGreaterThanOrEqual(2);
    rmSync(dir, { recursive: true });
  });
});

describe("MCP handshake", () => {
  const tools: McpToolDefinition[] = [
    {
      name: "check_migration_locks",
      description: "Classify SQL migration statements by Postgres lock mode.",
      inputSchema: {
        type: "object",
        properties: { sqlOrPath: { type: "string" } },
        required: ["sqlOrPath"],
        additionalProperties: false,
      },
      handler: () => ({ ok: true }),
    },
    {
      name: "rewrite_zero_downtime",
      description: "Rewrite risky migration SQL into expand/contract steps.",
      inputSchema: {
        type: "object",
        properties: { sqlOrPath: { type: "string" } },
        required: ["sqlOrPath"],
        additionalProperties: false,
      },
      mutates: true,
      handler: () => ({ ok: true }),
    },
  ];

  beforeEach(() => {
    jsonRpcFrameLog.length = 0;
    hijackStdoutForMcp();
    resetLoopBreaker();
    setGuards({ allowWrite: false, dryRun: false });
  });

  it("dry-run still runs read-only tools", async () => {
    setGuards({ dryRun: true, allowWrite: false });
    const readTool: McpToolDefinition = {
      name: "check_migration_locks",
      description: "d",
      inputSchema: { type: "object", properties: {} },
      handler: () => ({ ok: true, read: true }),
    };
    const ctx = {
      tools: [readTool],
      handlers: new Map([[readTool.name, readTool]]),
      toWsl: false,
      serverName: "pg-lock-xray",
      version: "0.1.0",
    };
    dispatchMcpMessage(
      {
        jsonrpc: "2.0",
        id: 9,
        method: "tools/call",
        params: { name: "check_migration_locks", arguments: {} },
      },
      ctx,
    );
    await new Promise((r) => setTimeout(r, 20));
    const frame = JSON.parse(jsonRpcFrameLog.at(-1) ?? "{}");
    expect(frame.result.content[0].text).toContain('"read": true');
  });

  it("initialize and tools/list", () => {
    const ctx = {
      tools,
      handlers: new Map(tools.map((t) => [t.name, t])),
      toWsl: false,
      serverName: "pg-lock-xray",
      version: "0.1.0",
    };
    dispatchMcpMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, ctx);
    dispatchMcpMessage({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, ctx);
    const list = JSON.parse(jsonRpcFrameLog[1]);
    expect(list.result.tools.map((t: { name: string }) => t.name)).toEqual([
      "check_migration_locks",
      "rewrite_zero_downtime",
    ]);
  });
});

describe("bridge blindajes", () => {
  beforeEach(() => {
    resetLoopBreaker();
    setGuards({ allowWrite: false, dryRun: false });
  });

  it("loop breaker on third identical call", () => {
    expect(checkLoopBreaker("t", { a: 1 })).toBeNull();
    expect(checkLoopBreaker("t", { a: 1 })).toBeNull();
    expect(checkLoopBreaker("t", { a: 1 })).toContain("LOOP_BREAKER");
  });

  it("blocks mutating without allow-write", () => {
    expect(guardMutatingTool({ mutates: true }).blocked).toBe(true);
    expect(guardMutatingTool({ annotations: { destructiveHint: true } }).blocked).toBe(true);
    setGuards({ allowWrite: true });
    expect(guardMutatingTool({ mutates: true }).blocked).toBe(false);
  });

  it("path normalization", () => {
    expect(windowsToWsl("D:\\data\\migrations\\a.sql")).toBe("/mnt/d/data/migrations/a.sql");
    expect(wslToWindows("/mnt/d/data/migrations/a.sql")).toBe("D:\\data\\migrations\\a.sql");
  });

  it("head+tail truncation and recency anchor", () => {
    const long = "H".repeat(200) + "T".repeat(200);
    const out = headTailTruncate(long, 200);
    expect(out).toContain("truncated");
    const anchor = buildRecencyAnchor([{ name: "check_migration_locks", summary: "Scan SQL" }]);
    const prompt = anchorPromptTail("SYSTEM\n...\nASSISTANT:", anchor);
    expect(prompt.indexOf(anchor)).toBeLessThan(prompt.lastIndexOf("ASSISTANT:"));
  });

  it("stream tool json abort", () => {
    const guard = new StreamToolJsonAbort();
    expect(guard.feed('<tool_call>{"name":"t","arguments":{')).toBe(false);
    expect(guard.feed("}}")).toBe(true);
  });

  it("strips thinking and reasoning policy", () => {
    const tag = "redacted_thinking";
    expect(stripRedactedThinking(`<${tag}>x</${tag}>ok`)).toBe("ok");
    const state = createReasoningState();
    const msgs = applyReasoningContentPolicy(
      [{ role: "assistant", content: "x", reasoning_content: "r" }],
      state,
      true,
    );
    expect(msgs[0].reasoning_content).toBeUndefined();
  });

  it("sanitize reasoner body and tool choice", () => {
    const body = sanitizeRequestBody({ temperature: 0.2, model: "deepseek-reasoner" }, true);
    expect(body.temperature).toBeUndefined();
    expect(normalizeToolChoice("required", detectProvider("https://dashscope.aliyuncs.com"))).toBe(
      "auto",
    );
  });

  it("normalize embed batch pads empty strings", async () => {
    const embed = vi.fn(async (batch: string[]) => batch.map(() => [1, 0, 0]));
    const vecs = await normalizeEmbedBatch(["a", "", "b"], {
      maxBatch: 2,
      dimensions: 3,
      embed,
    });
    expect(vecs.length).toBe(3);
    expect(vecs[1]).toEqual([0, 0, 0]);
  });

  it("embedding dimension fingerprint guard", async () => {
    await expect(
      normalizeEmbeddingsRequest({ input: ["x"], dimensions: 768, lockDimension: 1024 }, "ollama"),
    ).rejects.toThrow(/fingerprint/);
  });

  it("parseDirtyToolCall handles Qwen format", () => {
    const tools: McpToolDefinition[] = [
      {
        name: "check_migration_locks",
        description: "d",
        inputSchema: { type: "object", properties: {} },
        handler: () => ({}),
      },
    ];
    const raw = "✿FUNCTION✿: check_migration_locks\n✿ARGS✿: {\"sqlOrPath\":\"x\"}\n";
    expect(parseDirtyToolCall(raw, tools)?.name).toBe("check_migration_locks");
  });

  it("probeNCtx fallback", async () => {
    const fetchImpl = vi.fn(async () => ({ ok: false })) as typeof fetch;
    const r = await probeNCtx("http://127.0.0.1:9", fetchImpl);
    expect(r.source).toBe("fallback");
  });
});

describe("OpenAI-compat adapter", () => {
  it("blocks non-loopback LLM baseUrl by default", () => {
    expect(() => assertLoopbackLlmBaseUrl("https://api.openai.com")).toThrow(/Non-loopback/);
    expect(() => assertLoopbackLlmBaseUrl("http://127.0.0.1:11434")).not.toThrow();
  });

  it("strips thinking from chat completion", async () => {
    const tag = "redacted_thinking";
    const fetchImpl = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        choices: [
          {
            message: {
              content: `<${tag}>plan</${tag}>\nCREATE INDEX CONCURRENTLY idx ON t(c);`,
            },
          },
        ],
      }),
    })) as typeof fetch;
    const out = await callOpenAiCompatChat(
      "http://127.0.0.1:11434",
      { model: "local", messages: [] },
      fetchImpl,
    );
    expect(out).not.toContain("redacted_thinking");
    expect(out).toContain("CONCURRENTLY");
  });
});
