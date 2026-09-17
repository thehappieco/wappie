#!/usr/bin/env node
import { serveStdio } from '@modelcontextprotocol/server/stdio'
import { loadConfig, LocalConfigError } from './config.mjs'
import { createServer } from './server.mjs'

const argv = process.argv.slice(2)
if (argv.length === 1 && argv[0] === '--help') {
  process.stdout.write('wappie-mcp --config /absolute/path/config.json\nLocal read-only MCP over stdio. Credentials and plaintext opt-in belong in private configuration files, never command arguments.\n')
} else {
  try {
    if (argv.length !== 2 || argv[0] !== '--config') throw new LocalConfigError('config_argument_required')
    const config = await loadConfig(argv[1])
    const handle = serveStdio(() => createServer(config), { onerror: () => process.stderr.write('Wappie MCP: protocol error.\n') })
    const close = () => { void handle.close().finally(() => { process.exitCode = 0 }) }
    process.once('SIGINT', close); process.once('SIGTERM', close)
  } catch (error) {
    process.stderr.write(`Wappie MCP: ${error instanceof LocalConfigError ? error.code : 'startup_failed'}.\n`)
    process.exitCode = 1
  }
}
