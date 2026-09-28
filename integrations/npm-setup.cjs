// This program only transforms JSON on stdin. Rust owns file validation and writes.
'use strict';
const fs = require('node:fs');
const [action, environment, ...selected] = process.argv.slice(1);
const originalBytes = fs.readFileSync(0, 'utf8');
const fail = () => {
  process.stderr.write('Package setup conflicts with the current scripts or metadata. Review package.json and the setup documentation.\n');
  process.exit(1);
};
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
const wrap = (command, env) =>
  `envholster --env ${env} run -- /bin/sh -c ${quote(command + ' "$@"')} /bin/sh`;
try {
  const pkg = JSON.parse(originalBytes);
  if (!object(pkg) || !object(pkg.scripts)) fail();
  const key = 'envholsterSetup';
  const present = Object.hasOwn(pkg, key);
  const state = present ? pkg[key] : { version: 1, scripts: {} };
  if (!object(state) || state.version !== 1 || !object(state.scripts) ||
      Object.keys(state).some(k => !['version', 'scripts'].includes(k))) fail();
  for (const [name, record] of Object.entries(state.scripts)) {
    if (!object(record) || typeof record.original !== 'string' ||
        !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(record.environment) ||
        Object.keys(record).some(k => !['original', 'environment'].includes(k)) ||
        pkg.scripts[name] !== wrap(record.original, record.environment)) fail();
  }
  if (action === 'install') {
    for (const name of selected) {
      if (!/^[A-Za-z0-9][A-Za-z0-9:_-]{0,63}$/.test(name) ||
          !Object.hasOwn(pkg.scripts, name) || typeof pkg.scripts[name] !== 'string') fail();
      if (Object.hasOwn(state.scripts, name)) {
        if (state.scripts[name].environment !== environment) fail();
        continue;
      }
      const command = pkg.scripts[name];
      // Existing wrappers require human review, including indirect or compound ones.
      if (!command.trim() || /\benvholster\b/.test(command)) fail();
      Object.defineProperty(state.scripts, name, {
        value: { original: command, environment }, enumerable: true, writable: true,
      });
      pkg.scripts[name] = wrap(command, environment);
    }
    if (selected.length) pkg[key] = state;
  } else if (action === 'remove') {
    for (const [name, record] of Object.entries(state.scripts)) pkg.scripts[name] = record.original;
    delete pkg[key];
  } else if (action !== 'check') fail();
  if (action !== 'remove' && (Object.keys(state.scripts).length !== selected.length ||
      selected.some(name => !Object.hasOwn(state.scripts, name) || state.scripts[name].environment !== environment))) fail();
  if (action === 'check' || JSON.stringify(pkg) === JSON.stringify(JSON.parse(originalBytes))) {
    process.stdout.write(originalBytes);
  } else {
    const indent = originalBytes.match(/\n([\t ]+)"/)?.[1] || '  ';
    let result = JSON.stringify(pkg, null, indent) + '\n';
    if (originalBytes.includes('\r\n')) result = result.replace(/\n/g, '\r\n');
    process.stdout.write(result);
  }
} catch {
  fail();
}
