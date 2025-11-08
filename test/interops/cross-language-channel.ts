import * as fs from "fs";
import * as path from "path";
import { Buffer } from "buffer/";
import { MemoryStorage } from "../../src/MemoryStorage";
import { Channel } from "../../src/MemoryChannel";

/**
 * Cross-language channel that communicates with Rust via file-based IPC
 * Implements the Channel interface expected by IdManager
 */
export class CrossLanguageChannel implements Channel {
  private channelDir: string;
  private messageCounter: number = 0;
  private lastReadIndex: number = -1;
  private connectedCallbacks: Array<() => void> = [];

  constructor(channelName: string = "channel") {
    // Use a shared directory that both TypeScript and Rust can access
    // When __dirname is ".", use process.cwd(), otherwise use __dirname
    const baseDir = __dirname === "." ? process.cwd() : __dirname;
    this.channelDir = path.join(baseDir, "tmp", "channels", channelName);

    // Create channel directory if it doesn't exist
    if (!fs.existsSync(this.channelDir)) {
      fs.mkdirSync(this.channelDir, { recursive: true });
    }

    // Clear any existing messages
    this.clear();
  }

  /**
   * Start the channel (required by Channel interface)
   */
  async start(): Promise<void> {
    // File-based channel is ready immediately
    this.connectedCallbacks.forEach((cb) => cb());
    this.connectedCallbacks = [];
  }

  /**
   * Close the channel (required by Channel interface)
   */
  async close(): Promise<void> {
    this.clear();
  }

  /**
   * Register a callback for when the channel is connected
   */
  onConnected(callback: () => void): void {
    this.connectedCallbacks.push(callback);
  }

  /**
   * Get connection string for this channel
   */
  getConnectionString(): string {
    return this.channelDir;
  }

  /**
   * Create a channel from a connection string
   */
  fromConnectionString(conn: string, options?: any): Channel | null {
    const channelName = path.basename(conn);
    return new CrossLanguageChannel(channelName) as Channel;
  }

  /**
   * Send data to the channel (implements Channel.send)
   */
  async send(data: Buffer | Uint8Array): Promise<void> {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const messageId = Date.now() + "_" + this.messageCounter++;

    // Write to a file that Rust will read
    const filename = path.join(this.channelDir, `ts_to_rust_${messageId}.msg`);
    console.log(`[TS Channel] Writing to: ${filename}`);
    console.log(`[TS Channel] Channel dir exists: ${fs.existsSync(this.channelDir)}`);
    console.log(`[TS Channel] Data preview (first 100 bytes): ${buffer.toString("base64").substring(0, 100)}...`);
    const message = {
      id: messageId,
      timestamp: Date.now(),
      data: buffer.toString("base64"),
      length: buffer.length,
    };

    fs.writeFileSync(filename, JSON.stringify(message, null, 2));

    // Save a copy for debugging
    const debugDir = path.join(this.channelDir, "..", "debug");
    if (!fs.existsSync(debugDir)) {
      fs.mkdirSync(debugDir, { recursive: true });
    }
    const debugFile = path.join(debugDir, `sent_${path.basename(filename)}`);
    fs.copyFileSync(filename, debugFile);

    console.log(`[TS Channel] Sent message ${messageId} (${buffer.length} bytes)`);
    console.log(`[TS Channel] File created: ${fs.existsSync(filename)}`);
    console.log(`[TS Channel] Debug copy saved to: ${debugFile}`);
  }

  /**
   * Receive data from the channel (implements Channel.receive)
   */
  async receive(): Promise<Buffer> {
    console.log("[TS Channel] Waiting for message from Rust...");

    while (true) {
      // Look for messages from Rust
      const files = fs
        .readdirSync(this.channelDir)
        .filter((f) => f.startsWith("rust_to_ts_") && f.endsWith(".msg"))
        .sort();

      if (files.length > 0) {
        // Find the first unread message
        for (const file of files) {
          const filepath = path.join(this.channelDir, file);

          try {
            const content = fs.readFileSync(filepath, "utf8");
            const message = JSON.parse(content);

            // Save a copy for debugging before deleting
            const debugDir = path.join(this.channelDir, "..", "debug");
            if (!fs.existsSync(debugDir)) {
              fs.mkdirSync(debugDir, { recursive: true });
            }
            const debugFile = path.join(debugDir, `received_${path.basename(filepath)}`);
            fs.copyFileSync(filepath, debugFile);

            // Delete the file after reading
            fs.unlinkSync(filepath);

            console.log(`[TS Channel] Received message ${message.id} (${message.length} bytes)`);
            console.log(`[TS Channel] Debug copy saved to: ${debugFile}`);
            return Buffer.from(message.data, "base64");
          } catch (err) {
            console.error(`[TS Channel] Error reading message:`, err);
          }
        }
      }

      // Wait a bit before checking again
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  /**
   * Clear all messages in the channel
   */
  clear() {
    try {
      const files = fs.readdirSync(this.channelDir);
      files.forEach((file) => {
        if (file.endsWith(".msg")) {
          fs.unlinkSync(path.join(this.channelDir, file));
        }
      });
    } catch (err) {
      // Directory might not exist yet
    }
  }

  /**
   * Get the channel directory path for Rust to use
   */
  getChannelPath(): string {
    return this.channelDir;
  }
}

// Test script
if (require.main === module) {
  import("../../src/IdManager").then(async ({ default: IdManager }) => {
    const { default: VaultysId } = await import("../../src/VaultysId");

    console.log("\n=== TypeScript IdManager Cross-Language Test ===\n");

    // Parse command line arguments
    const args = process.argv.slice(2);
    const role = args[0] || "acceptor";
    const channelName = args[1] || "test-channel";

    // Create IdManager
    const vaultysId = await VaultysId.generatePerson();
    const manager = new IdManager(vaultysId, MemoryStorage());
    manager.setProtocolVersion(1);
    manager.name = role === "acceptor" ? "Bob (TypeScript)" : "Alice (TypeScript)";
    manager.email = role === "acceptor" ? "bob@typescript.com" : "alice@typescript.com";

    console.log("TypeScript IdManager created:");
    console.log(`  Role: ${role}`);
    console.log(`  DID: ${manager.vaultysId.did}`);
    console.log(`  Name: ${manager.name}`);
    console.log(`  Email: ${manager.email}`);

    // Create cross-language channel
    const channel = new CrossLanguageChannel(channelName);
    console.log(`\nChannel created at: ${channel.getChannelPath()}`);
    console.log(`Channel directory exists: ${fs.existsSync(channel.getChannelPath())}`);
    try {
      const contents = fs.readdirSync(channel.getChannelPath());
      console.log(`Channel directory contents: ${contents.length > 0 ? contents.join(", ") : "empty"}`);
    } catch (e: any) {
      console.log(`Channel directory contents: (unable to read: ${e.message})`);
    }

    try {
      if (role === "acceptor") {
        console.log("\n[TS] Starting acceptContact protocol...");
        console.log("[TS] Waiting for connection request from Rust...\n");

        // Start the channel
        await channel.start();

        // Create metadata for the accept request
        const metadata = {
          name: manager.name || "Bob (TypeScript)",
          email: manager.email || "bob@typescript.com",
          role: "acceptor",
        };

        // Accept contact from Rust
        let result;
        try {
          result = await manager.acceptContact(channel as Channel);
          console.log("\n[TS] ✅ acceptContact completed successfully!");
          console.log(`[TS] Result:`, result.did);
        } catch (error: any) {
          console.log("\n[TS] ❌ acceptContact failed!");
          console.log(`[TS] Error:`, error.message);

          // Log debug info
          const debugDir = path.join(channel.getChannelPath(), "..", "debug");
          console.log(`\n[TS] Debug files saved in: ${debugDir}`);
          if (fs.existsSync(debugDir)) {
            const files = fs.readdirSync(debugDir);
            console.log(`[TS] Debug files:`, files);
          }
          throw error;
        }

        // Check saved contacts
        const contacts = manager.contacts;
        console.log(`[TS] Contacts saved: ${contacts.length}`);
        if (contacts.length > 0) {
          console.log(`[TS] Contact details:`);
          contacts.forEach((contact: any) => {
            console.log(`  - DID: ${contact.did}`);
            // Get metadata from IdManager for this contact
            const contactMetadata = manager.getContactMetadatas(contact.did);
            if (contactMetadata) {
              console.log(`    Name: ${contactMetadata.name || "N/A"}`);
              console.log(`    Email: ${contactMetadata.email || "N/A"}`);
            }
          });
        }
      } else {
        console.log("\n[TS] Starting askContact protocol...");

        // Start the channel
        await channel.start();

        // Create metadata for the ask request
        const metadata = {
          name: manager.name || "Alice (TypeScript)",
          email: manager.email || "alice@typescript.com",
          role: "asker",
        };

        // Ask contact from Rust
        const result = await manager.askContact(channel as Channel);

        console.log("\n[TS] ✅ askContact completed successfully!");
        console.log(`[TS] Result:`, result.did);
      }
    } catch (error) {
      console.error("\n[TS] ❌ Protocol failed:", error);
      process.exit(1);
    }

    console.log("\n[TS] Test completed successfully!");
    process.exit(0);
  });
}
