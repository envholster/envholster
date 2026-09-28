'use strict';
try {
  const pkg = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  const next = Object.hasOwn(deps, 'next');
  const vite = Object.hasOwn(deps, 'vite');
  const profile = next && vite ? 'ambiguous' : next ? 'nextjs' : vite ? 'vite' : '';
  const manager = typeof pkg.packageManager === 'string' ? pkg.packageManager.match(/^(npm|pnpm|yarn|bun)@/)?.[1] || '' : '';
  const scripts = Object.keys(pkg.scripts || {}).filter(k => /^[A-Za-z0-9][A-Za-z0-9:_-]{0,63}$/.test(k));
  // Injection cannot replace an explicitly required file. Automatic cleanup
  // waits for a deliberate compatibility setup for these launch commands.
  const fileReaders = scripts.filter(k => typeof pkg.scripts[k] === 'string' &&
    /(?:--env-file(?:=|\s)|\b(?:dotenv|env-cmd)\b|(?:^|[\s=:'"/])\.env(?:\b|\.))/.test(pkg.scripts[k]));
  process.stdout.write(`profile=${profile}\nmanager=${manager}\nscripts=${scripts.join(',')}\nfile_readers=${fileReaders.join(',')}\n`);
} catch {
  process.exit(1);
}
