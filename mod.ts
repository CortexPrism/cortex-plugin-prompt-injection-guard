import type { Tool, ToolContext, PluginContext, ToolCallResult } from "cortex/plugins";

let detectionThreshold: string;
let blockOnDetect: boolean;
let logInjections: boolean;

export async function onLoad(ctx: PluginContext): Promise<void> {
  const threshold = await ctx.config.get("detectionThreshold");
  const block = await ctx.config.get("blockOnDetect");
  const log = await ctx.config.get("logInjections");

  detectionThreshold = threshold || "medium";
  blockOnDetect = block !== "false";
  logInjections = log !== "false";

  console.log(`[cortex-plugin-prompt-injection-guard] Loaded (threshold: ${detectionThreshold}, block: ${blockOnDetect}, log: ${logInjections})`);
}

export async function onUnload(_ctx: PluginContext): Promise<void> {
  console.log("[cortex-plugin-prompt-injection-guard] Unloading...");
}

interface InjectionPattern {
  name: string;
  category: string;
  pattern: RegExp;
  severity: "low" | "medium" | "high";
  description: string;
}

const injectionPatterns: InjectionPattern[] = [
  { name: "ignore-previous-instructions", category: "direct", pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|directives?|commands?|prompts?)/i, severity: "high", description: "Attempt to override prior instructions" },
  { name: "you-are-now", category: "direct", pattern: /you\s+are\s+now\s+(a\s+)?/i, severity: "high", description: "Role redefinition attempt" },
  { name: "new-instructions", category: "direct", pattern: /(here\s+are|follow|obey)\s+(my\s+)?new\s+(instructions?|rules?|directives?)/i, severity: "high", description: "New instruction injection" },
  { name: "system-prompt-leak", category: "direct", pattern: /(reveal|show|display|print|output|tell\s+me)\s+(your\s+)?(system\s+)?(prompt|instructions?|directives?)/i, severity: "high", description: "System prompt disclosure attempt" },
  { name: "act-as", category: "direct", pattern: /\bact\s+as\s+(if\s+you\s+are\s+)?(a\s+|an\s+)?/i, severity: "medium", description: "Persona override attempt" },
  { name: "pretend-you-are", category: "direct", pattern: /pretend\s+(you\s+are|to\s+be)\b/i, severity: "medium", description: "Pretend role injection" },
  { name: "forget-everything", category: "direct", pattern: /forget\s+(everything|all\s+previous|your\s+training)/i, severity: "high", description: "Memory reset attempt" },
  { name: "imagine-you-are", category: "direct", pattern: /imagine\s+(you\s+are|yourself\s+as)\b/i, severity: "medium", description: "Imagination-based role injection" },

  { name: "url-payload-injection", category: "indirect", pattern: /https?:\/\/\S*(?:prompt|inject|override|command|system)\S*/i, severity: "medium", description: "URL-based payload injection" },
  { name: "markdown-image-exploit", category: "indirect", pattern: /!\[.*?\]\(\s*(?:https?:\/\/|data:).*?(?:prompt|inject|instruction)/i, severity: "medium", description: "Markdown image with injection payload" },
  { name: "data-exfiltration", category: "indirect", pattern: /(?:send|forward|copy|paste|exfiltrate)\s+.*?\b(?:to\s+)?(?:https?:\/\/|webhook|endpoint|server)/i, severity: "high", description: "Data exfiltration attempt" },

  { name: "base64-content", category: "encoding", pattern: /(?:[A-Za-z0-9+/]{20,}={0,2})/g, severity: "low", description: "Potential Base64 encoded content" },
  { name: "url-encoding", category: "encoding", pattern: /%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2})+/g, severity: "low", description: "URL-encoded content" },
  { name: "hex-encoding", category: "encoding", pattern: /\\x[0-9A-Fa-f]{2}(?:\\x[0-9A-Fa-f]{2})+/g, severity: "low", description: "Hex-encoded content" },

  { name: "system-delimiter", category: "boundary", pattern: /---?\s*SYSTEM\s*---?/i, severity: "high", description: "System delimiter injection" },
  { name: "role-switching", category: "boundary", pattern: /(?:switch|change)\s+(?:role|mode|persona|context)\s+(?:to|into)\b/i, severity: "medium", description: "Role switching attempt" },
  { name: "delimiter-injection", category: "boundary", pattern: /<\/?(?:system|instruction|prompt|rule|directive)>/i, severity: "medium", description: "XML delimiter injection" },

  { name: "email-exfiltration", category: "exfiltration", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b.*?\b(?:send|output|print|echo)\b/i, severity: "high", description: "Email-based data exfiltration" },
  { name: "webhook-exfiltration", category: "exfiltration", pattern: /(?:discord|slack|telegram|webhook)\..*?(?:api|hook|send)/i, severity: "high", description: "Webhook data exfiltration" },

  { name: "jailbreak-prefix", category: "direct", pattern: /^(?:DAN|Developer\s+Mode|Jailbreak|Unrestricted)\b/im, severity: "high", description: "Known jailbreak prefix" },
  { name: "confirmation-bypass", category: "direct", pattern: /(?:do\s+not\s+(?:ask|confirm|verify|check)|without\s+(?:asking|confirming|verification))/i, severity: "high", description: "Confirmation bypass attempt" },
  { name: "output-override", category: "direct", pattern: /(?:start\s+your\s+response\s+with|your\s+output\s+must|you\s+must\s+output|respond\s+with\s+exactly)/i, severity: "high", description: "Output format override" },
  { name: "hidden-instruction", category: "direct", pattern: /(?:hidden|secret|covert)\s+(?:instruction|prompt|command|rule)/i, severity: "high", description: "Hidden instruction reference" },
  { name: "bypass-filter", category: "direct", pattern: /(?:bypass|circumvent|get\s+around|work\s+around)\s+(?:the\s+)?(?:filter|safety|guard|restriction|rule)/i, severity: "high", description: "Filter bypass attempt" },
  { name: "token-smuggling", category: "direct", pattern: /(?:split\s+(?:this|the|your)\s+(?:response|output|message)|respond\s+in\s+(?:parts|pieces|segments))/i, severity: "medium", description: "Token smuggling attempt" },
  { name: "meta-instruction", category: "boundary", pattern: /\[\[(?:system|override|inject|instruction|command)\s*[:=]\s*.*?\]\]/i, severity: "high", description: "Meta-instruction bracket injection" },
  { name: "crescendo-attack", category: "direct", pattern: /(?:let's|let\s+us)\s+(?:play\s+a\s+game|do\s+a\s+roleplay|have\s+a\s+conversation\s+where)/i, severity: "medium", description: "Crescendo-style social engineering" },
  { name: "unicode-homoglyph", category: "encoding", pattern: /[\u0400-\u04FF\u2000-\u206F\uFF00-\uFFEF]{2,}/g, severity: "low", description: "Unicode homoglyph content" },
  { name: "zero-width", category: "encoding", pattern: /[\u200B-\u200F\u2028\u2029\uFEFF]/g, severity: "low", description: "Zero-width character content" },
];

const whitelistedPatterns: Set<string> = new Set();
const detectionStats = {
  total: 0,
  blocked: 0,
  byCategory: {} as Record<string, number>,
};

function getThresholdMultiplier(): number {
  switch (detectionThreshold) {
    case "low": return 0.5;
    case "high": return 1.5;
    default: return 1.0;
  }
}

function scanText(text: string, contextFilter: string): { detected: InjectionPattern[]; score: number } {
  const multiplier = getThresholdMultiplier();
  const detected: InjectionPattern[] = [];
  let score = 0;

  for (const ip of injectionPatterns) {
    if (whitelistedPatterns.has(ip.name)) continue;

    if (contextFilter !== "all" && ip.category === "indirect" && contextFilter === "user_input") continue;
    if (contextFilter === "tool_output" && ip.category === "exfiltration") {
      if (ip.pattern.test(text)) {
        detected.push(ip);
      }
      continue;
    }

    const matches = text.match(ip.pattern);
    if (matches) {
      const weight = ip.severity === "high" ? 10 : ip.severity === "medium" ? 5 : 2;
      score += weight * matches.length * multiplier;
      detected.push(ip);
    }
  }

  return { detected, score };
}

export async function preMiddleware(
  args: Record<string, unknown>,
  _ctx: ToolContext
): Promise<ToolCallResult | void> {
  if (!blockOnDetect) return;

  for (const [key, value] of Object.entries(args)) {
    if (typeof value !== "string") continue;
    const { detected, score } = scanText(value, "user_input");

    if (score >= 15) {
      detectionStats.total++;
      detectionStats.blocked++;
      for (const ip of detected) {
        detectionStats.byCategory[ip.category] = (detectionStats.byCategory[ip.category] || 0) + 1;
      }

      if (logInjections) {
        console.warn(`[injection-guard] BLOCKED: score=${score}, patterns=${detected.map((d) => d.name).join(", ")}`);
      }

      return {
        toolName: "preMiddleware",
        success: false,
        output: "",
        error: `Prompt injection detected (score: ${score}). Request blocked by injection guard.`,
        durationMs: 0,
      };
    }
  }
}

const injectionScanTool: Tool = {
  definition: {
    name: "injection_scan",
    description: "Scan text for prompt injection attempts using built-in detection patterns",
    params: [
      { name: "text", type: "string", description: "Text to scan for injection attempts", required: true },
      { name: "context", type: "string", description: "Context of the text being scanned", required: false },
    ],
    capabilities: [],
  },
  execute: async (args: Record<string, unknown>, _ctx: ToolContext): Promise<ToolCallResult> => {
    const start = Date.now();
    try {
      const text = args.text as string;
      const context = (args.context as string) || "user_input";

      if (!text) {
        return { toolName: "injection_scan", success: false, output: "", error: "text is required", durationMs: Date.now() - start };
      }

      const { detected, score } = scanText(text, context);

      const output = JSON.stringify({
        textLength: text.length,
        context,
        score,
        threshold: detectionThreshold,
        detectedPatterns: detected.map((d) => ({ name: d.name, category: d.category, severity: d.severity, description: d.description })),
        verdict: score >= 15 ? "BLOCK" : score >= 5 ? "WARN" : "PASS",
      }, null, 2);

      return { toolName: "injection_scan", success: true, output, durationMs: Date.now() - start };
    } catch (error) {
      return { toolName: "injection_scan", success: false, output: "", error: `Scan failed: ${error instanceof Error ? error.message : String(error)}`, durationMs: Date.now() - start };
    }
  },
};

const injectionPatternsTool: Tool = {
  definition: {
    name: "injection_patterns",
    description: "List active prompt injection detection patterns",
    params: [
      { name: "category", type: "string", description: "Filter patterns by category", required: false },
    ],
    capabilities: [],
  },
  execute: async (args: Record<string, unknown>, _ctx: ToolContext): Promise<ToolCallResult> => {
    const start = Date.now();
    try {
      const category = args.category as string | undefined;

      const filtered = category
        ? injectionPatterns.filter((p) => p.category === category)
        : injectionPatterns;

      const output = JSON.stringify({
        total: filtered.length,
        whitelisted: whitelistedPatterns.size,
        patterns: filtered.map((p) => ({
          name: p.name,
          category: p.category,
          severity: p.severity,
          description: p.description,
          active: !whitelistedPatterns.has(p.name),
        })),
      }, null, 2);

      return { toolName: "injection_patterns", success: true, output, durationMs: Date.now() - start };
    } catch (error) {
      return { toolName: "injection_patterns", success: false, output: "", error: `List patterns failed: ${error instanceof Error ? error.message : String(error)}`, durationMs: Date.now() - start };
    }
  },
};

const injectionWhitelistTool: Tool = {
  definition: {
    name: "injection_whitelist",
    description: "Manage the injection whitelist (list, add, or remove patterns)",
    params: [
      { name: "action", type: "string", description: "Whitelist action to perform", required: false },
      { name: "pattern", type: "string", description: "Pattern to add or remove from whitelist", required: false },
      { name: "reason", type: "string", description: "Reason for whitelist change", required: false },
    ],
    capabilities: [],
  },
  execute: async (args: Record<string, unknown>, _ctx: ToolContext): Promise<ToolCallResult> => {
    const start = Date.now();
    try {
      const action = (args.action as string) || "list";
      const pattern = args.pattern as string | undefined;

      if (action === "list") {
        return {
          toolName: "injection_whitelist",
          success: true,
          output: JSON.stringify({ whitelisted: Array.from(whitelistedPatterns), count: whitelistedPatterns.size }, null, 2),
          durationMs: Date.now() - start,
        };
      }

      if (!pattern) {
        return { toolName: "injection_whitelist", success: false, output: "", error: "pattern is required for add/remove actions", durationMs: Date.now() - start };
      }

      if (action === "add") {
        whitelistedPatterns.add(pattern);
        return { toolName: "injection_whitelist", success: true, output: `Added "${pattern}" to whitelist`, durationMs: Date.now() - start };
      }

      if (action === "remove") {
        const removed = whitelistedPatterns.delete(pattern);
        return { toolName: "injection_whitelist", success: true, output: removed ? `Removed "${pattern}" from whitelist` : `Pattern "${pattern}" not in whitelist`, durationMs: Date.now() - start };
      }

      return { toolName: "injection_whitelist", success: false, output: "", error: `Unknown action: ${action}`, durationMs: Date.now() - start };
    } catch (error) {
      return { toolName: "injection_whitelist", success: false, output: "", error: `Whitelist operation failed: ${error instanceof Error ? error.message : String(error)}`, durationMs: Date.now() - start };
    }
  },
};

const injectionStatsTool: Tool = {
  definition: {
    name: "injection_stats",
    description: "Get prompt injection detection statistics",
    params: [
      { name: "since", type: "string", description: "ISO date to filter statistics from", required: false },
    ],
    capabilities: [],
  },
  execute: async (args: Record<string, unknown>, _ctx: ToolContext): Promise<ToolCallResult> => {
    const start = Date.now();
    try {
      const since = args.since as string | undefined;

      const output = JSON.stringify({
        since: since || "session start",
        totalDetections: detectionStats.total,
        totalBlocked: detectionStats.blocked,
        blockRate: detectionStats.total > 0 ? `${Math.round((detectionStats.blocked / detectionStats.total) * 100)}%` : "0%",
        byCategory: detectionStats.byCategory,
        activePatternCount: injectionPatterns.length - whitelistedPatterns.size,
        whitelistedCount: whitelistedPatterns.size,
        threshold: detectionThreshold,
      }, null, 2);

      return { toolName: "injection_stats", success: true, output, durationMs: Date.now() - start };
    } catch (error) {
      return { toolName: "injection_stats", success: false, output: "", error: `Stats failed: ${error instanceof Error ? error.message : String(error)}`, durationMs: Date.now() - start };
    }
  },
};

export const tools: Tool[] = [
  injectionScanTool,
  injectionPatternsTool,
  injectionWhitelistTool,
  injectionStatsTool,
];
