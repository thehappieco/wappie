// The websocket client.
//
// One read loop owns the connection, and frames are routed by request id and
// type. Anything else reading directly would steal frames from the stream —
// which is the bug this shape exists to prevent: fetching a content key
// mid-stream must not consume the messages that arrive while it waits.

import { websocketURL } from './endpoint'
import * as P from './protocol'

export interface ConnectOptions {
  /** Empty means this page's own origin, which is what the dev proxy sets up. */
  serverURL: string
  /**
   * Either credential the server takes: an API key belongs to a program and
   * lives until revoked, a session belongs to a person and expires.
   */
  credential: { kind: 'api_key' | 'session'; token: string }
  clientID?: string
  onFrame?: (frame: P.Frame) => void
  onClose?: (reason: string) => void
}

export class ProtocolError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message)
    this.name = 'ProtocolError'
  }
}

interface Waiter {
  resolve: (frame: P.Frame) => void
  reject: (err: Error) => void
}

const REQUEST_TIMEOUT = 20_000

export class Connection {
  private waiters = new Map<string, Waiter>()
  private streams = new Map<string, (frame: P.Frame) => void>()
  private counter = 0
  private closed = false

  private constructor(
    private readonly socket: WebSocket,
    readonly welcome: P.Welcome,
    private readonly opts: ConnectOptions,
  ) {
    this.socket.onmessage = (event) => this.receive(event)
    this.socket.onclose = (event) => this.finish(event.reason || `código ${event.code}`)
    this.socket.onerror = () => this.finish('a conexão falhou')
  }

  static connect(opts: ConnectOptions): Promise<Connection> {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(websocketURL(opts.serverURL))

      // The code matters as much as the message. A caller retries a transport
      // failure and must not retry a rejected key — so a server that is simply
      // down is never reported as unauthorized. Only the server saying so is.
      const fail = (code: string, message: string) => {
        socket.onopen = socket.onmessage = socket.onerror = socket.onclose = null
        try {
          socket.close()
        } catch {
          // Already closing; nothing to report to a socket that is gone.
        }
        reject(new ProtocolError(code, message))
      }

      socket.onerror = () => fail(P.ErrInternal, 'não foi possível abrir a conexão')
      socket.onclose = (event) =>
        fail(P.ErrInternal, event.reason || 'a conexão fechou antes do welcome')

      socket.onopen = () => {
        const hello: P.Hello =
          opts.credential.kind === 'session'
            ? { session: opts.credential.token, version: P.VERSION, client_id: opts.clientID ?? 'web' }
            : { api_key: opts.credential.token, version: P.VERSION, client_id: opts.clientID ?? 'web' }
        socket.send(JSON.stringify({ t: P.TypeHello, r: 'hello', p: hello }))
      }

      // The welcome is read here rather than through the waiter map, because
      // until it arrives there is no session to route anything into.
      socket.onmessage = (event) => {
        let frame: P.Frame
        try {
          frame = JSON.parse(String(event.data)) as P.Frame
        } catch {
          fail(P.ErrBadRequest, 'o servidor respondeu algo que não é JSON')
          return
        }
        if (frame.t === P.TypeError) {
          const err = frame.p as P.WireError
          socket.onclose = null
          socket.close()
          reject(new ProtocolError(err.code, err.message))
          return
        }
        if (frame.t !== P.TypeWelcome) {
          fail(P.ErrBadRequest, `esperava ${P.TypeWelcome}, veio ${frame.t}`)
          return
        }
        socket.onopen = socket.onerror = socket.onclose = null
        resolve(new Connection(socket, frame.p as P.Welcome, opts))
      }
    })
  }

  get isOpen(): boolean {
    return !this.closed && this.socket.readyState === WebSocket.OPEN
  }

  /** send fires a frame without waiting for anything. */
  send(type: string, reqID: string, payload: unknown): void {
    if (!this.isOpen) throw new ProtocolError(P.ErrInternal, 'a conexão está fechada')
    this.socket.send(JSON.stringify({ t: type, r: reqID, p: payload }))
  }

  /**
   * request sends a frame and resolves with the reply of the expected type.
   *
   * The waiter is registered before the send, so a reply that arrives
   * immediately cannot be routed to the push stream and lost.
   */
  async request<T>(type: string, payload: unknown, wantType: string): Promise<T> {
    const reqID = `r${++this.counter}`
    const wantKey = routeKey(reqID, wantType)
    const errKey = routeKey(reqID, P.TypeError)

    const frame = await new Promise<P.Frame>((resolve, reject) => {
      if (!this.isOpen) {
        reject(new ProtocolError(P.ErrInternal, 'a conexão está fechada'))
        return
      }
      const settle = (fn: () => void) => {
        this.waiters.delete(wantKey)
        this.waiters.delete(errKey)
        clearTimeout(timer)
        fn()
      }
      const timer = setTimeout(
        () => settle(() => reject(new ProtocolError(P.ErrInternal, `${type} não respondeu`))),
        REQUEST_TIMEOUT,
      )

      this.waiters.set(wantKey, {
        resolve: (f) => settle(() => resolve(f)),
        reject: (e) => settle(() => reject(e)),
      })
      this.waiters.set(errKey, {
        resolve: (f) =>
          settle(() => {
            const err = f.p as P.WireError
            reject(new ProtocolError(err.code, err.message))
          }),
        reject: (e) => settle(() => reject(e)),
      })

      this.socket.send(JSON.stringify({ t: type, r: reqID, p: payload }))
    })

    return frame.p as T
  }

  /**
   * stream sends one request and keeps receiving replies to it.
   *
   * Pairing is the reason it exists. It answers with a code, then another code
   * twenty seconds later, then success or a timeout — several frames sharing
   * one request id over a couple of minutes, which the request/reply map above
   * cannot express: it resolves once and forgets the id, and every frame after
   * the first would fall through to the push handler.
   *
   * The returned function stops listening. It does not stop the server, so a
   * caller that is cancelling a pairing has to say so on the wire as well.
   */
  stream(type: string, payload: unknown, onFrame: (frame: P.Frame) => void): () => void {
    if (!this.isOpen) throw new ProtocolError(P.ErrInternal, 'a conexão está fechada')
    const reqID = `s${++this.counter}`
    this.streams.set(reqID, onFrame)
    this.socket.send(JSON.stringify({ t: type, r: reqID, p: payload }))
    return () => {
      this.streams.delete(reqID)
    }
  }

  close(reason = 'encerrado pelo cliente'): void {
    if (this.closed) return
    this.closed = true
    try {
      this.socket.close(1000, reason)
    } catch {
      // Closing a socket that already went away is not worth raising.
    }
  }

  private receive(event: MessageEvent): void {
    let frame: P.Frame
    try {
      frame = JSON.parse(String(event.data)) as P.Frame
    } catch {
      return
    }
    const waiter = frame.r ? this.waiters.get(routeKey(frame.r, frame.t)) : undefined
    if (waiter) {
      waiter.resolve(frame)
      return
    }
    const stream = frame.r ? this.streams.get(frame.r) : undefined
    if (stream) {
      stream(frame)
      return
    }
    this.opts.onFrame?.(frame)
  }

  private finish(reason: string): void {
    if (this.closed) return
    this.closed = true
    for (const waiter of this.waiters.values()) {
      waiter.reject(new ProtocolError(P.ErrInternal, `a conexão fechou: ${reason}`))
    }
    this.waiters.clear()
    // A stream has no promise to reject, so its listener is told the same way
    // the server would have told it: with an error frame carrying no id.
    for (const stream of this.streams.values()) {
      stream({
        t: P.TypeError,
        p: { code: P.ErrInternal, message: `a conexão fechou: ${reason}` },
      })
    }
    this.streams.clear()
    this.opts.onClose?.(reason)
  }
}

function routeKey(reqID: string, type: string): string {
  return `${reqID} ${type}`
}
