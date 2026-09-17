/** Applications may translate protocol diagnostics without a UI dependency. */
export type MessageValues = Record<string, string | number | undefined>
export type MessageResolver = (source: string, values?: MessageValues) => string
let resolver: MessageResolver | undefined
export function setMessageResolver(value?: MessageResolver): void { resolver = value }
export function t(source: string, values?: MessageValues): string {
  if (resolver) return resolver(source, values)
  return values ? source.replace(/\{(\w+)\}/g, (match, key: string) => values[key] === undefined ? match : String(values[key])) : source
}
