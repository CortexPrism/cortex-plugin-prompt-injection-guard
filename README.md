# cortex-plugin-prompt-injection-guard

Scans user and tool inputs for prompt injection attempts with 30+ detection patterns across 5
categories.

## Installation

```bash
cortex plugin install marketplace:cortex-plugin-prompt-injection-guard
cortex plugin install github:CortexPrism/cortex-plugin-prompt-injection-guard
cortex plugin install ./manifest.json
```

## Tools

### injection_scan

Scan text for injection attempts.

**Parameters:**

- `text` (string, required) — Text to scan
- `context` (string, default: "user_input") — One of: user_input, tool_output, system_message, all

### injection_patterns

List active detection patterns.

**Parameters:**

- `category` (string, optional) — Filter: direct, indirect, encoding, boundary, exfiltration

### injection_whitelist

Manage the whitelist.

**Parameters:**

- `action` (string, default: "list") — list, add, remove
- `pattern` (string, optional) — Pattern to add/remove
- `reason` (string, optional) — Reason for change

### injection_stats

Get detection statistics.

**Parameters:**

- `since` (string, optional) — ISO date filter

## Detection Categories

| Category          | Patterns | Examples                                                                                                     |
| ----------------- | -------- | ------------------------------------------------------------------------------------------------------------ |
| Direct            | 10       | ignore previous instructions, you are now, act as, forget everything, DAN/jailbreak                          |
| Indirect          | 3        | URL payload injection, markdown exploits, data exfiltration                                                  |
| Encoding          | 4        | Base64, URL encoding, hex encoding, Unicode homoglyphs, zero-width chars                                     |
| Boundary          | 3        | ---SYSTEM--- delimiters, role switching, XML delimiter injection                                             |
| Exfiltration      | 2        | Email/webhook data exfiltration attempts                                                                     |
| Direct (extended) | 8        | Confirmation bypass, output override, hidden instructions, filter bypass, token smuggling, crescendo attacks |

## Pre-Middleware

When `blockOnDetect` is enabled, `preMiddleware` scans all tool args before execution and blocks
requests with a detection score >= 15.

## Configuration

UI settings:

- **Detection Threshold** (select, default: medium) — Low/Medium/High sensitivity
- **Block On Detection** (boolean, default: true) — Block tool execution
- **Log Injections** (boolean, default: true) — Log all detections

## Capabilities

- `tools` — Injection scanning tools
- `middleware:pre` — Pre-execution injection guard

## Development

```bash
deno task test
deno task validate
```

## License

MIT
