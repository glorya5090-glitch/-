import fs from 'node:fs';
import path from 'node:path';

interface ResolveCliVersionOptions {
  cwd?: string;
  scriptPath?: string | null;
}

function candidatePackageJsonPaths({
  cwd = process.cwd(),
  scriptPath = process.argv[1],
}: ResolveCliVersionOptions): string[] {
  const candidates: string[] = [];

  if (typeof scriptPath === 'string' && scriptPath.trim()) {
    const normalizedScriptPath = path.resolve(cwd, scriptPath);
    candidates.push(path.resolve(path.dirname(normalizedScriptPath), '..', 'package.json'));

    try {
      const realScriptPath = fs.realpathSync.native(normalizedScriptPath);
      candidates.unshift(path.resolve(path.dirname(realScriptPath), '..', 'package.json'));
    } catch {
      // Fall back to the original argv path when it cannot be resolved.
    }
  }

  candidates.push(path.resolve(cwd, 'package.json'));
  return [...new Set(candidates)];
}

export function resolveCliVersion(options: ResolveCliVersionOptions = {}): string {
  for (const packageJsonPath of candidatePackageJsonPaths(options)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) as { version?: unknown };
      if (typeof parsed.version === 'string' && parsed.version.trim()) {
        return parsed.version;
      }
    } catch {
      // Try the next candidate.
    }
  }

  return 'unknown';
}
