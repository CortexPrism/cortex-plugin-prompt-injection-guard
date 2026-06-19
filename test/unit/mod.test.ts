import { assertEquals } from 'https://deno.land/std@0.208.0/assert/mod.ts';
import { tools } from '../../mod.ts';
import type { PluginContext, ToolContext } from '../../types.ts';

// Mock PluginContext
const mockContext: PluginContext & ToolContext = {
  pluginId: 'cortex-plugin-prompt-injection-guard',
  pluginDir: '/tmp/plugins/cortex-plugin-prompt-injection-guard',
  state: {
    get: async () => null,
    set: async () => {},
    delete: async () => {},
    list: async () => ({}),
  },
  config: {
    get: async () => null,
    set: async () => {},
    getAll: async () => ({}),
  },
  logger: {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
  },
  host: {
    registerTool: () => {},
    unregisterTool: () => {},
  },
  sessionId: 'test-session',
  workingDir: '/tmp',
  agentId: 'test-agent',
  workspaceDir: '/tmp',
};

function findTool(name: string) {
  const tool = tools.find((t) => t.definition.name === name);
  if (!tool) throw new Error(`Tool "${name}" not found`);
  return tool;
}

Deno.test('tools array — exports all tools', () => {
  assertEquals(tools.length >= 1, true);
});

Deno.test('injection_scan — rejects empty text', async () => {
  const tool = findTool('injection_scan');
  const result = await tool.execute({ 'text': '' }, mockContext);
  assertEquals(result.success, false);
  assertEquals(result.success, false);
});

Deno.test('injection_patterns — tool is defined with name and description', () => {
  const tool = findTool('injection_patterns');
  assertEquals(typeof tool.definition.description, 'string');
  assertEquals(tool.definition.description.length > 0, true);
});

Deno.test('injection_whitelist — tool is defined with name and description', () => {
  const tool = findTool('injection_whitelist');
  assertEquals(typeof tool.definition.description, 'string');
  assertEquals(tool.definition.description.length > 0, true);
});

Deno.test('injection_stats — tool is defined with name and description', () => {
  const tool = findTool('injection_stats');
  assertEquals(typeof tool.definition.description, 'string');
  assertEquals(tool.definition.description.length > 0, true);
});

Deno.test('all tools return durationMs', async () => {
  for (const tool of tools) {
    const args: Record<string, unknown> = {};
    const result = await tool.execute(args, mockContext);
    assertEquals(typeof result.durationMs, 'number');
    assertEquals(result.durationMs >= 0, true);
  }
});
