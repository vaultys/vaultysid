import IdManager from "../src/IdManager";
import VaultysId from "../src/VaultysId";
import { Buffer } from "buffer/";
import * as fs from "fs";
import * as path from "path";

// Shared memory channel that can be used by both TypeScript and Rust
// through file-based communication
class SharedMemoryChannel {
  private channelDir: string;
  private messageCounter: number = 0;

  constructor(channelName: string = "interop-channel") {
    this.channelDir = path.join(__dirname, "..", "tmp", channelName);

    // Create channel directory if it doesn't exist
    if (!fs.existsSync(this.channelDir)) {
      fs.mkdirSync(this.channelDir, { recursive: true });
    }

    // Clear any existing messages
    this.clear();
  }

  // Send a message by writing to a file
  async send(data: Buffer): Promise<void> {
    const messageId = this.messageCounter++;
    const filename = path.join(this.channelDir, `msg_${messageId}.json`);

    const message = {
      id: messageId,
      timestamp: Date.now(),
      data: data.toString("base64"),
    };

    fs.writeFileSync(filename, JSON.stringify(message));
    console.log(`[TS] Sent message ${messageId} (${data.length} bytes)`);
  }

  // Receive a message by reading from files
  async receive(): Promise<Buffer> {
    while (true) {
      const files = fs.readdirSync(this.channelDir)
        .filter(f => f.startsWith("response_"))
        .sort();

      if (files.length > 0) {
        const filename = path.join(this.channelDir, files[0]);
        const content = fs.readFileSync(filename, "utf8");
        const message = JSON.parse(content);

        // Delete the file after reading
        fs.unlinkSync(filename);

        console.log(`[TS] Received response ${message.id}`);
        return Buffer.from(message.data, "base64");
      }

      // Wait a bit before checking again
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  // Clear all messages
  clear() {
    const files = fs.readdirSync(this.channelDir);
    files.forEach(f => {
      fs.unlinkSync(path.join(this.channelDir, f));
    });
  }

  // Get channel directory for Rust side
  getChannelPath(): string {
    return this.channelDir;
  }
}

// Test the ask/accept protocol through shared memory
async function testMemoryProtocol() {
  console.log("\n🚀 TypeScript-Rust Memory Interop Test\n");

  // Create TypeScript IdManager
  const tsId = await VaultysId.generatePerson();
  const tsManager = await IdManager.fromVaultysId(tsId);
  tsManager.name = "Alice (TypeScript)";
  tsManager.email = "alice@typescript.com";
  tsManager.phone = "+1234567890";

  console.log("TypeScript IdManager created:");
  console.log(`  DID: ${tsManager.vaultysId.did}`);
  console.log(`  Name: ${tsManager.name}`);
  console.log(`  Email: ${tsManager.email}`);

  // Create shared memory channel
  const channel = new SharedMemoryChannel("test-channel");
  console.log(`\nChannel created at: ${channel.getChannelPath()}`);

  // Export TypeScript manager data for Rust to use
  const tsManagerData = {
    id: tsManager.vaultysId.id.toString("hex"),
    did: tsManager.vaultysId.did,
    secret: tsManager.vaultysId.getSecret().toString("hex"),
    name: tsManager.name,
    email: tsManager.email,
    phone: tsManager.phone,
  };

  const exportPath = path.join(channel.getChannelPath(), "ts_manager.json");
  fs.writeFileSync(exportPath, JSON.stringify(tsManagerData, null, 2));
  console.log("\nExported TypeScript manager data for Rust");

  // Simulate SRP protocol messages
  console.log("\n--- Starting Protocol Exchange ---\n");

  // 1. Send initial connection request
  const connectRequest = {
    type: "CONNECT",
    from: tsManager.vaultysId.did,
    name: tsManager.name,
    email: tsManager.email,
  };
  await channel.send(Buffer.from(JSON.stringify(connectRequest)));

  // 2. Wait for Rust response
  console.log("Waiting for Rust response...");
  const response = await channel.receive();
  const responseData = JSON.parse(response.toString());
  console.log(`Received response: ${responseData.type}`);

  if (responseData.type === "CHALLENGE") {
    // 3. Sign the challenge
    const signature = await tsManager.vaultysId.signChallenge(
      Buffer.from(responseData.challenge, "base64")
    );

    // 4. Send signed response
    const signedResponse = {
      type: "RESPONSE",
      signature: signature.toString("base64"),
      from: tsManager.vaultysId.did,
    };
    await channel.send(Buffer.from(JSON.stringify(signedResponse)));

    // 5. Wait for final acceptance
    const finalResponse = await channel.receive();
    const finalData = JSON.parse(finalResponse.toString());

    if (finalData.type === "ACCEPT") {
      console.log("\n✅ Protocol completed successfully!");

      // Save Rust manager as contact
      await tsManager.saveContact({
        did: finalData.did,
        metadata: {
          name: finalData.name || "",
          email: finalData.email || "",
        },
      });

      // Display results
      const contacts = await tsManager.contacts;
      console.log(`\nContacts saved: ${contacts.length}`);
      if (contacts.length > 0) {
        console.log("Contact details:");
        contacts.forEach(contact => {
          console.log(`  - DID: ${contact.did}`);
          console.log(`    Name: ${contact.metadata?.name || "N/A"}`);
          console.log(`    Email: ${contact.metadata?.email || "N/A"}`);
        });
      }

      // Export final state
      const finalState = {
        success: true,
        tsManager: {
          did: tsManager.vaultysId.did,
          name: tsManager.name,
          contacts: contacts.length,
        },
        rustManager: {
          did: finalData.did,
          name: finalData.name,
          email: finalData.email,
        },
      };

      const statePath = path.join(channel.getChannelPath(), "final_state.json");
      fs.writeFileSync(statePath, JSON.stringify(finalState, null, 2));
      console.log(`\nFinal state saved to: ${statePath}`);

    } else {
      console.log(`\n❌ Protocol failed: ${finalData.type}`);
    }
  }

  // Clean up
  console.log("\n--- Protocol Test Complete ---\n");
}

// Run the test
if (require.main === module) {
  testMemoryProtocol().catch((error) => {
    console.error("Error:", error);
    process.exit(1);
  });
}

export { SharedMemoryChannel, testMemoryProtocol };
