---
name: add-plugin
description: Use this skill when the user wants to add, refactor, or generalize a `agentpay <plugin>` integration like Bitrefill. Follow the shared plugin registration path under `src/plugins`, keep plugin-specific API or scraping code under `src/lib/<plugin>` or `src/lib/<plugin>/`, reuse the existing Rust daemon signing and policy path through the shared CLI plugin context instead of reimplementing signing, and add focused CLI tests for the new plugin.
---

# Add Plugin

Use this skill when the task is "add another plugin like Bitrefill" or "make plugin onboarding more reusable."

## Ground Truth

- `src/cli.ts` is the main CLI entrypoint, but plugin-specific command trees should not be wired inline there.
- `src/plugins/types.ts` defines the shared `CliPluginContext` and the generic plugin registrar shape.
- `src/plugins/index.ts` is the registry for built-in plugins.
- `src/plugins/bitrefill.ts` is the reference implementation for a plugin that owns its own command tree.
- Plugin-specific HTTP or browser/bootstrap code belongs in `src/lib/<plugin>.ts` or `src/lib/<plugin>/`.
- Signing, policy checks, manual approval handling, and raw transaction broadcast plumbing stay on the existing AgentPay path exposed through `CliPluginContext`.

## Default Architecture

1. Create `src/plugins/<plugin>.ts`.
2. Register the plugin in `src/plugins/index.ts`.
3. Keep plugin-local API normalization, transports, cookies, scraping, or challenge handling in `src/lib/<plugin>*`.
4. Keep `src/cli.ts` responsible only for assembling shared dependencies and calling `registerBuiltinCliPlugins(...)`.
5. Reuse `context.agent.runJson(...)` plus `context.broadcast.*` for any payment flow that reaches the daemon.

## Implementation Rules

- Do not add another large inline `.command('<plugin>')` block to `src/cli.ts`.
- Do not reimplement signing, nonce management, or policy logic in the plugin.
- If the plugin needs onchain payment, default to preview-first behavior and make live payment explicit with `--broadcast`.
- If the plugin only needs a quote plus an optional live payment path, prefer one `buy`-style command over a redundant separate `price` command.
- Keep plugin-specific error handling inside the plugin module when possible.
- If a remote API needs browser bootstrap, Cloudflare handling, or cookies, isolate that behind the plugin's transport/client layer instead of leaking it into the shared CLI.
- Pass only shared helpers through `CliPluginContext`; keep plugin business logic inside the plugin module.

## Deterministic Workflow

1. Inspect `src/plugins/bitrefill.ts` to copy the current plugin structure and command style.
2. Add or extend the plugin client under `src/lib/<plugin>*`.
3. Add a new `CliPlugin` implementation under `src/plugins/<plugin>.ts`.
4. Register it in `src/plugins/index.ts`.
5. If the plugin needs signing or broadcast, use `context.config`, `context.agent`, and `context.broadcast` instead of shelling around the shared flow.
6. Add a focused CLI test file or extend the closest existing one under `test/`.
7. Run the plugin-focused tests and at least one `agentpay <plugin> --help` smoke check.

## Testing Rule

- Prefer mocked CLI/integration tests over live third-party dependencies.
- Cover command registration, happy path output, unsupported modes, and any explicit challenge or approval state.
- If the plugin supports `--broadcast`, cover both preview-only and broadcast-backed flows.

## References

- Read `src/plugins/types.ts` for the shared context contract.
- Read `src/plugins/index.ts` for plugin registration.
- Read `src/plugins/bitrefill.ts` for the current plugin pattern.
- Read the matching `src/lib/<plugin>*` module only when implementing that plugin's remote API behavior.
