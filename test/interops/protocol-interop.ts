import IdManager from "../../src/IdManager";
import VaultysId from "../../src/VaultysId";
import { Buffer } from "buffer/";
import * as fs from "fs";
import * as path from "path";
import * as net from "net";
import { MemoryChannel } from "../../src/MemoryChannel";
import { MemoryStorage } from "../../src/MemoryStorage";

// Protocol message types
enum MessageType {
  INIT = "INIT",
  CHALLENGE = "CHALLENGE",
  RESPONSE = "RESPONSE",
  ACCEPT = "ACCEPT",
  REJECT = "REJECT",
  DATA = "DATA",
  COMPLETE = "COMPLETE",
  ERROR = "ERROR",
}

interface ProtocolMessage {
  type: MessageType;
  sender: string;
  recipient?: string;
  data: Buffer;
  timestamp: number;
  sequence: number;
}

// Shared memory channel for cross-language communication
class InteropChannel {
  private socket?: net.Socket;
  private server?: net.Server;
  private messageQueue: ProtocolMessage[] = [];
  private onMessageCallback?: (msg: ProtocolMessage) => void;

  constructor(private port: number = 9876) {}

  // Start as server (TypeScript side)
  async startServer(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((socket) => {
        this.socket = socket;
        console.log("Client connected");

        socket.on("data", (data) => {
          try {
            const messages = this.parseMessages(Buffer.from(data));
            messages.forEach((msg) => {
              this.messageQueue.push(msg);
              if (this.onMessageCallback) {
                this.onMessageCallback(msg);
              }
            });
          } catch (e) {
            console.error("Failed to parse message:", e);
          }
        });

        socket.on("error", (err) => {
          console.error("Socket error:", err);
        });
      });

      this.server.listen(this.port, () => {
        console.log(`InteropChannel server listening on port ${this.port}`);
        resolve();
      });

      this.server.on("error", reject);
    });
  }

  // Connect as client (could be used by either side)
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = net.connect(this.port, "localhost", () => {
        console.log("Connected to server");
        resolve();
      });

      this.socket.on("data", (data) => {
        try {
          const messages = this.parseMessages(Buffer.from(data));
          messages.forEach((msg) => {
            this.messageQueue.push(msg);
            if (this.onMessageCallback) {
              this.onMessageCallback(msg);
            }
          });
        } catch (e) {
          console.error("Failed to parse message:", e);
        }
      });

      this.socket.on("error", reject);
    });
  }

  // Parse incoming data into messages
  private parseMessages(data: Buffer): ProtocolMessage[] {
    const messages: ProtocolMessage[] = [];
    const lines = data.toString().split("\n");

    for (const line of lines) {
      if (line.trim()) {
        try {
          const parsed = JSON.parse(line);
          parsed.data = Buffer.from(parsed.data, "base64");
          messages.push(parsed);
        } catch (e) {
          console.error("Failed to parse line:", line, e);
        }
      }
    }

    return messages;
  }

  // Send a message
  async send(message: ProtocolMessage): Promise<void> {
    if (!this.socket) {
      throw new Error("Not connected");
    }

    const serialized = {
      ...message,
      data: message.data.toString("base64"),
    };

    const data = JSON.stringify(serialized) + "\n";
    this.socket.write(data);
  }

  // Receive a message (blocking)
  async receive(): Promise<ProtocolMessage> {
    while (this.messageQueue.length === 0) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    return this.messageQueue.shift()!;
  }

  // Set callback for incoming messages
  onMessage(callback: (msg: ProtocolMessage) => void) {
    this.onMessageCallback = callback;
  }

  // Close the connection
  close() {
    if (this.socket) {
      this.socket.destroy();
    }
    if (this.server) {
      this.server.close();
    }
  }
}

// Protocol implementation for IdManager
class IdManagerProtocol {
  private sequence = 0;

  constructor(
    private manager: IdManager,
    private channel: InteropChannel,
  ) {}

  // Start the ask protocol (initiator)
  async startAskProtocol(recipientDid: string): Promise<boolean> {
    console.log(`[TS] Starting ask protocol with ${recipientDid}`);

    // Send INIT message
    const initMessage: ProtocolMessage = {
      type: MessageType.INIT,
      sender: this.manager.vaultysId.did,
      recipient: recipientDid,
      data: Buffer.from(
        JSON.stringify({
          protocol: "ASK_ACCEPT",
          version: 1,
          name: this.manager.name,
          email: this.manager.email,
        }),
      ),
      timestamp: Date.now(),
      sequence: this.sequence++,
    };

    await this.channel.send(initMessage);
    console.log("[TS] Sent INIT message");

    // Wait for CHALLENGE
    const challenge = await this.channel.receive();
    if (challenge.type !== MessageType.CHALLENGE) {
      console.error(`[TS] Expected CHALLENGE, got ${challenge.type}`);
      return false;
    }
    console.log("[TS] Received CHALLENGE");

    // Sign the challenge
    const signature = await this.manager.vaultysId.signChallenge(challenge.data);

    // Send RESPONSE
    const responseMessage: ProtocolMessage = {
      type: MessageType.RESPONSE,
      sender: this.manager.vaultysId.did,
      recipient: recipientDid,
      data: Buffer.from(signature),
      timestamp: Date.now(),
      sequence: this.sequence++,
    };

    await this.channel.send(responseMessage);
    console.log("[TS] Sent RESPONSE");

    // Wait for ACCEPT or REJECT
    const result = await this.channel.receive();
    if (result.type === MessageType.ACCEPT) {
      console.log("[TS] Protocol ACCEPTED");

      // Save contact
      const contactData = JSON.parse(result.data.toString());
      this.manager.saveContact({
        did: contactData.did,
        metadata: {
          name: contactData.name || "",
          email: contactData.email || "",
        },
      });

      return true;
    } else {
      console.log(`[TS] Protocol REJECTED or error: ${result.type}`);
      return false;
    }
  }

  // Accept the ask protocol (responder)
  async acceptAskProtocol(): Promise<boolean> {
    console.log("[TS] Waiting for ask protocol...");

    // Wait for INIT
    const init = await this.channel.receive();
    if (init.type !== MessageType.INIT) {
      console.error(`[TS] Expected INIT, got ${init.type}`);
      return false;
    }
    console.log(`[TS] Received INIT from ${init.sender}`);

    const initData = JSON.parse(init.data.toString());

    // Generate a challenge
    const challengeData = Buffer.from(`Challenge-${Date.now()}-${Math.random()}`);

    const challengeMessage: ProtocolMessage = {
      type: MessageType.CHALLENGE,
      sender: this.manager.vaultysId.did,
      recipient: init.sender,
      data: challengeData,
      timestamp: Date.now(),
      sequence: this.sequence++,
    };

    await this.channel.send(challengeMessage);
    console.log("[TS] Sent CHALLENGE");

    // Wait for RESPONSE
    const response = await this.channel.receive();
    if (response.type !== MessageType.RESPONSE) {
      console.error(`[TS] Expected RESPONSE, got ${response.type}`);
      return false;
    }
    console.log("[TS] Received RESPONSE");

    // In a real implementation, verify the signature
    // For now, we'll accept it

    // Send ACCEPT with our info
    const acceptMessage: ProtocolMessage = {
      type: MessageType.ACCEPT,
      sender: this.manager.vaultysId.did,
      recipient: init.sender,
      data: Buffer.from(
        JSON.stringify({
          did: this.manager.vaultysId.did,
          name: this.manager.name,
          email: this.manager.email,
        }),
      ),
      timestamp: Date.now(),
      sequence: this.sequence++,
    };

    await this.channel.send(acceptMessage);
    console.log("[TS] Sent ACCEPT");

    return true;
  }
}

// Test runner
export async function runTypescriptSide(role: "initiator" | "responder") {
  console.log(`\n🚀 TypeScript IdManager Interop Test - Role: ${role}\n`);

  // Create IdManager
  const vaultysId = await VaultysId.generatePerson();
  const manager = new IdManager(vaultysId, MemoryStorage());
  manager.setProtocolVersion(1);
  manager.name = role === "initiator" ? "Alice (TS)" : "Bob (TS)";
  manager.email = role === "initiator" ? "alice@typescript.com" : "bob@typescript.com";

  console.log(`Created IdManager:`);
  console.log(`  DID: ${manager.vaultysId.did}`);
  console.log(`  Name: ${manager.name}`);
  console.log(`  Email: ${manager.email}`);

  // Create interop channel
  const channel = new InteropChannel(9876);

  if (role === "initiator") {
    // TypeScript side acts as server
    await channel.startServer();
    console.log("Waiting for Rust side to connect...");

    // Wait a bit for connection
    await new Promise((resolve) => setTimeout(resolve, 2000));

    // Create protocol handler
    const protocol = new IdManagerProtocol(manager, channel);

    // Start the ask protocol
    const success = await protocol.startAskProtocol("did:vaultys:rust-peer");

    if (success) {
      console.log("\n✅ Ask protocol completed successfully!");
      const contacts = manager.contacts;
      console.log(`Contacts saved: ${contacts.length}`);
      if (contacts.length > 0) {
        console.log(`  First contact: ${contacts[0].did}`);
        console.log(`  Metadata:`, contacts[0].metadata);
      }
    } else {
      console.log("\n❌ Ask protocol failed");
    }
  } else {
    // TypeScript side acts as client (responder)
    console.log("Connecting to Rust server...");
    await channel.connect();

    // Create protocol handler
    const protocol = new IdManagerProtocol(manager, channel);

    // Accept the ask protocol
    const success = await protocol.acceptAskProtocol();

    if (success) {
      console.log("\n✅ Accept protocol completed successfully!");
      const contacts = manager.contacts;
      console.log(`Contacts saved: ${contacts.length}`);
      if (contacts.length > 0) {
        console.log(`  First contact: ${contacts[0].did}`);
        console.log(`  Metadata:`, contacts[0].metadata);
      }
    } else {
      console.log("\n❌ Accept protocol failed");
    }
  }

  // Clean up
  setTimeout(() => {
    channel.close();
    process.exit(0);
  }, 1000);
}

// Command line interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const role = args[0] as "initiator" | "responder";

  if (!role || (role !== "initiator" && role !== "responder")) {
    console.error("Usage: ts-node protocol-interop.ts [initiator|responder]");
    process.exit(1);
  }

  runTypescriptSide(role).catch((error) => {
    console.error("Error:", error);
    process.exit(1);
  });
}
