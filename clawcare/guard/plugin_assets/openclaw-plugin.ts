/**
 * ClawCare Guard — OpenClaw plugin.
 *
 * This TypeScript plugin is installed by `clawcare guard activate --platform openclaw`
 * into `~/.openclaw/extensions/clawcare-guard/index.ts`.
 *
 * At activation time the placeholder `__CLAWCARE_BIN__` is replaced with the
 * fully-resolved path to the `clawcare` binary (e.g.
 * `/opt/homebrew/Caskroom/miniconda/base/bin/clawcare`).  This ensures the
 * plugin works even when the binary is not on the default PATH (conda envs,
 * pyenv shims, etc.).
 *
 * It registers `before_tool_call` and `after_tool_call` hooks that shell out
 * to `clawcare guard run` for pre-command scanning and post-exec audit
 * logging.
 *
 * Reference:
 *   https://docs.openclaw.ai/concepts/agent-loop#hook-points
 *   https://docs.openclaw.ai/tools/plugin#plugin-hooks
 */

import { execSync, execFileSync } from "child_process";
import { existsSync } from "fs";

export const id = "clawcare-guard";
export const name = "ClawCare Guard";

/** Resolved at activation time by `clawcare guard activate`. */
const CLAWCARE_BIN = "__CLAWCARE_BIN__";

function resolveBin(logger: any): string {
  if (CLAWCARE_BIN.startsWith("/") && !existsSync(CLAWCARE_BIN)) {
    logger.warn(
      `[clawcare-guard] binary not found at ${CLAWCARE_BIN} — ` +
        "was it moved?  Re-run:  clawcare guard activate --platform openclaw",
    );
  }
  return CLAWCARE_BIN;
}

export default function register(api: any) {
  const logger = api.logger ?? console;
  const bin = resolveBin(logger);

  // ── before_tool_call ─────────────────────────────────────────
  // Intercept exec/tool calls before they run.  If ClawCare returns
  // exit code 2, block the tool call.
  // Uses api.on() (typed hook API) to bypass the internal hook gate
  // that requires config.hooks.internal.enabled === true.
  api.on(
    "before_tool_call",
    async (event: any, ctx: any) => {
      const command = extractCommand(event);
      if (!command) return; // nothing to scan

      try {
        // `clawcare guard run` exits 0 = allow, 2 = block
        execSync(`${bin} guard run -- ${shellEscape(command)}`, {
          stdio: ["pipe", "pipe", "pipe"],
          timeout: 10_000,
        });
        // exit 0 → allow
      } catch (err: any) {
        if (err.status === 2) {
          // ClawCare blocked the command
          const reason =
            err.stderr?.toString().trim() ||
            err.stdout?.toString().trim() ||
            "Blocked by ClawCare guard";
          return {
            block: true,
            blockReason: reason,
          };
        }
        // Non-2 error → log and allow (fail-open)
        logger.warn(`[clawcare-guard] scan error: ${err.message}`);
      }
    },
    { priority: 100 },
  );

  // ── after_tool_call ──────────────────────────────────────────
  // Post-exec audit: log the command + exit code for the audit trail.
  api.on(
    "after_tool_call",
    async (event: any, ctx: any) => {
      const command = extractCommand(event);
      if (!command) return;

      try {
        const input = JSON.stringify({
          tool: event.toolName ?? "exec",
          input: { command },
          output: { exit_code: event.exitCode ?? event.result?.exitCode ?? null },
          duration_ms: event.durationMs ?? null,
        });

        execSync(
          `${bin} guard hook --platform openclaw --stage post`,
          {
            input,
            stdio: ["pipe", "pipe", "pipe"],
            timeout: 5_000,
          },
        );
      } catch {
        // Post-exec logging is best-effort; never block on failure.
      }
    },
    { priority: 100 },
  );
}

// ── helpers ──────────────────────────────────────────────────────

function extractCommand(ctx: any): string | undefined {
  // OpenClaw exec tool puts the command in ctx.params.command or ctx.input.command
  return (
    ctx?.params?.command ??
    ctx?.input?.command ??
    ctx?.toolInput?.command ??
    undefined
  );
}

function shellEscape(s: string): string {
  // Wrap in single quotes, escaping embedded single quotes.
  return "'" + s.replace(/'/g, "'\\''") + "'";
}
