#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { execute } from './lib.mjs'

async function hidden(prompt) {
  if (!process.stdin.isTTY) throw new Error('Password input requires a terminal or --password-file')
  process.stderr.write(prompt)
  process.stdin.setEncoding('utf8'); process.stdin.setRawMode(true); process.stdin.resume()
  return new Promise((resolve, reject) => {
    let value = ''
    const finish = (error) => {
      process.stdin.off('data', onData); process.stdin.setRawMode(false); process.stdin.pause(); process.stderr.write('\n')
      if (error) reject(error); else resolve(value)
    }
    const onData = chunk => {
      for (const char of chunk.toString('utf8')) {
        if (char === '\u0003') { finish(new Error('Cancelled')); return }
        if (char === '\r' || char === '\n') { finish(); return }
        if (char === '\u007f' || char === '\b') value = value.slice(0, -1)
        else if (char >= ' ') value += char
      }
    }
    process.stdin.on('data', onData)
  })
}
try {
  await execute(process.argv.slice(2), {
    secret: hidden,
    readJSON: async path => { if (path !== '-') return readFile(path, 'utf8'); let text = ''; for await (const chunk of process.stdin) text += chunk; return text },
    print: value => process.stdout.write(typeof value === 'string' ? value + '\n' : JSON.stringify(value, null, 2) + '\n'),
  })
} catch (error) {
  process.stderr.write(`wsctl: ${error.message}\n`)
  process.exitCode = 1
}
