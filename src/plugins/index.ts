import type { Command } from 'commander';
import { bitrefillCliPlugin } from './bitrefill.js';
import { registerCliPlugins, type CliPluginContext } from './types.js';

const BUILTIN_CLI_PLUGINS = [bitrefillCliPlugin];

export function registerBuiltinCliPlugins(program: Command, context: CliPluginContext): void {
  registerCliPlugins(program, context, BUILTIN_CLI_PLUGINS);
}
