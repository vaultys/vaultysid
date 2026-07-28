/**
 * TCP-based Channel implementation for cross-container communication.
 *
 * Implements the same { start, close, send, receive } interface as
 * MemoryChannel, but over a TCP socket so two Docker containers (or
 * processes) can perform SRP + ExecutionManager flows.
 *
 * Usage:
 *   Server side:  TcpChannel.listen(port)   → Promise<TcpChannel>
 *   Client side:  TcpChannel.connect(host, port) → Promise<TcpChannel>
 */

import * as net from "net";
import { Buffer } from "buffer/";
import type { Channel } from "../../src/MemoryChannel";

export class TcpChannel implements Channel {
  private socket: net.Socket | null = null;
  private server: net.Server | null = null;
  private messageQueue: Buffer[] = [];
  private waiters: Array<(data: Buffer) => void> = [];
  private connectedCallbacks: Array<() => void> = [];
  private closed = false;
  private pendingData: Buffer = Buffer.alloc(0);

  // ── Factory methods ──

  /**
   * Server side: listen on a port and resolve once a client connects.
   */
  static listen(port: number, host = "0.0.0.0"): Promise<TcpChannel> {
    return new Promise((resolve, reject) => {
      const ch = new TcpChannel();
      ch.server = net.createServer((socket) => {
        // Stop accepting further connections on this server
        ch.server?.close();
        ch.socket = socket;
        ch._wire(socket);
        ch.connectedCallbacks.forEach((cb) => cb());
        ch.connectedCallbacks = [];
        resolve(ch);
      });
      ch.server.on("error", reject);
      ch.server.listen(port, host, () => {
        console.log(`[TcpChannel] Listening on ${host}:${port}`);
      });
    });
  }

  /**
   * Client side: connect to a remote host:port.
   */
  static connect(host: string, port: number): Promise<TcpChannel> {
    return new Promise((resolve, reject) => {
      const ch = new TcpChannel();
      const socket = net.createConnection({ host, port }, () => {
        ch.socket = socket;
        ch._wire(socket);
        ch.connectedCallbacks.forEach((cb) => cb());
        ch.connectedCallbacks = [];
        console.log(`[TcpChannel] Connected to ${host}:${port}`);
        resolve(ch);
      });
      socket.on("error", reject);
    });
  }

  // ── Channel interface ──

  async start(): Promise<void> {
    // Already started via listen/connect
  }

  async close(): Promise<void> {
    this.closed = true;
    // Unblock any pending waiters with empty buffer
    for (const waiter of this.waiters) {
      waiter(Buffer.alloc(0));
    }
    this.waiters = [];
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    if (this.server) {
      this.server.close();
      this.server = null;
    }
  }

  async send(data: Buffer): Promise<void> {
    if (!this.socket || this.closed) throw new Error("TcpChannel: not connected");
    // Length-prefixed framing: 4-byte big-endian length + payload
    const header = Buffer.alloc(4);
    header.writeUInt32BE(data.length, 0);
    this.socket.write(header);
    this.socket.write(data);
  }

  receive(): Promise<Buffer> {
    if (this.closed) return Promise.resolve(Buffer.alloc(0));

    // If there is already a message queued, return it immediately
    if (this.messageQueue.length > 0) {
      return Promise.resolve(this.messageQueue.shift()!);
    }

    // Otherwise, block until one arrives
    return new Promise<Buffer>((resolve) => {
      this.waiters.push(resolve);
    });
  }

  onConnected(callback: () => void): void {
    if (this.socket) {
      callback();
    } else {
      this.connectedCallbacks.push(callback);
    }
  }

  getConnectionString(): string {
    return "";
  }

  fromConnectionString(_conn: string, _options?: any): Channel | null {
    return null;
  }

  // ── Internal ──

  private _wire(socket: net.Socket): void {
    socket.on("data", (chunk: globalThis.Buffer) => {
      // Accumulate incoming bytes and extract length-prefixed frames
      this.pendingData = Buffer.concat([this.pendingData, Buffer.from(chunk)]);

      while (this.pendingData.length >= 4) {
        const frameLen = this.pendingData.readUInt32BE(0);
        if (this.pendingData.length < 4 + frameLen) break; // incomplete frame

        const frame = this.pendingData.slice(4, 4 + frameLen);
        this.pendingData = Buffer.from(this.pendingData.slice(4 + frameLen));

        // Dispatch
        if (this.waiters.length > 0) {
          this.waiters.shift()!(frame);
        } else {
          this.messageQueue.push(frame);
        }
      }
    });

    socket.on("close", () => {
      this.closed = true;
      for (const waiter of this.waiters) {
        waiter(Buffer.alloc(0));
      }
      this.waiters = [];
    });

    socket.on("error", (err) => {
      console.error("[TcpChannel] Socket error:", err.message);
    });
  }
}
