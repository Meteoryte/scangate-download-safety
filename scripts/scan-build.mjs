#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { WORKSPACE_ROOT } from './scan-core.mjs';

const pinPath = path.join(WORKSPACE_ROOT, 'docker/skillspector.pin.json');
const pin = JSON.parse(fs.readFileSync(pinPath, 'utf8'));

function run(args) {
  const result = spawnSync('docker', args, {
    cwd: WORKSPACE_ROOT,
    encoding: 'utf8',
    stdio: 'inherit',
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

run([
  'build',
  '-f', 'docker/skillspector.Dockerfile',
  '--build-arg', 'SKILLSPECTOR_REF=' + pin.ref,
  '-t', 'skillspector:' + pin.ref,
  '.',
]);
run(['tag', 'skillspector:' + pin.ref, 'skillspector:pinned']);
run(['build', '-f', 'docker/detonator.Dockerfile', '-t', 'detonator:pinned', '.']);

console.log('Built skillspector:pinned at ' + pin.ref + ' and detonator:pinned.');
