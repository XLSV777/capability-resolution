#!/usr/bin/env node
// capability-resolution-check <resolver origin> [--json] [--need "<job>"] [--timeout <ms>]
// capability-resolution-check --server <origin> [--json] [--timeout <ms>]
// Exit code 0 when the target reaches resolver-1 (or server-1 with --server), 1 otherwise (2 for usage errors).
import { checkResolver, checkServer, formatReport } from '../src/check.js';

const args = process.argv.slice(2);
const flag = (name) => { const i = args.indexOf(name); if (i < 0) return undefined; const v = args[i + 1]; args.splice(i, 2); return v; };
const json = args.includes('--json');
if (json) args.splice(args.indexOf('--json'), 1);
const server = flag('--server');
const need = flag('--need');
const timeout = flag('--timeout');
const usage = () => {
  process.stderr.write('usage: capability-resolution-check <resolver origin> [--json] [--need "<job>"] [--timeout <ms>]\n'
    + '       capability-resolution-check --server <origin> [--json] [--timeout <ms>]\n');
  process.exit(2);
};
const timeoutMs = timeout ? Number(timeout) : undefined;
let rep;
if (server !== undefined) {
  if (!server || server.startsWith('-') || args.length || need !== undefined) usage();
  rep = await checkServer(server, { timeoutMs });
} else {
  if (args.length !== 1 || args[0].startsWith('-')) usage();
  rep = await checkResolver(args[0], { need, timeoutMs });
}
process.stdout.write((json ? JSON.stringify(rep, null, 2) : formatReport(rep)) + '\n');
process.exit(rep.level === 'resolver-1' || rep.level === 'server-1' ? 0 : 1);
