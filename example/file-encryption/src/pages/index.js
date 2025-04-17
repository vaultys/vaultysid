import { useEffect, useState, useRef } from "react";
import { IdManager, VaultysId, LocalStorage } from "@vaultys/id";
export default function Home() {
  const [idManager, setIdManager] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("encrypt");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const fileInputRef = useRef(null);

  useEffect(() => {
    async function initVaultysId() {
      try {
        setLoading(true);
        const storage = LocalStorage("vaultysStorage");

        if (storage.get("secret") || storage.get("entropy")) {
          // ID already exists, load it
          const manager = await IdManager.fromStore(storage);
          setIdManager(manager);
        } else {
          // Need to create a new ID
          setIsCreating(true);
        }
      } catch (err) {
        console.error("Error initializing VaultysID:", err);
        setError("Failed to initialize VaultysID: " + err.message);
      } finally {
        setLoading(false);
      }
    }

    initVaultysId();
  }, []);

  async function createWebAuthnId() {
    try {
      setLoading(true);
      setError("");

      const storage = LocalStorage("vaultysStorage");

      // Try to create with WebAuthn
      let vaultysId;
      try {
        // Create a WebAuthn credential if supported
        vaultysId = await VaultysId.createWebauthn(true);
        if (!vaultysId) {
          throw new Error("WebAuthn credential creation failed");
        }
      } catch (err) {
        console.warn("WebAuthn not available, falling back to software key:", err);
        vaultysId = await VaultysId.generatePerson();
      }

      const manager = new IdManager(vaultysId, storage);
      setIdManager(manager);
      setIsCreating(false);
    } catch (err) {
      console.error("Error creating VaultysID:", err);
      setError("Failed to create VaultysID: " + err.message);
    } finally {
      setLoading(false);
    }
  }

  async function createSoftwareId() {
    try {
      setLoading(true);
      setError("");

      const storage = LocalStorage("vaultysStorage");
      const vaultysId = await VaultysId.generatePerson();
      const manager = new IdManager(vaultysId, storage);

      setIdManager(manager);
      setIsCreating(false);
    } catch (err) {
      console.error("Error creating VaultysID:", err);
      setError("Failed to create VaultysID: " + err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleFileChange(e) {
    const selectedFile = e.target.files[0];
    if (!selectedFile) return;

    try {
      setFile({
        file: selectedFile,
        name: selectedFile.name,
        type: selectedFile.type,
        arrayBuffer: await selectedFile.arrayBuffer(),
      });
      setResult(null);
      setError("");
    } catch (err) {
      console.error("Error reading file:", err);
      setError("Failed to read file: " + err.message);
    }
  }

  async function resetIdentity() {
    if (confirm("Are you sure you want to reset your VaultysID? This action cannot be undone.")) {
      localStorage.removeItem("vaultysStorage");
      setIdManager(null);
      setIsCreating(true);
      setFile(null);
      setResult(null);
    }
  }

  async function handleEncryptFile() {
    if (!file || !idManager) {
      setError("Please select a file first");
      return;
    }

    try {
      setLoading(true);
      setError("");

      // Create a mock channel that our ID will communicate with itself
      const mockChannel = {
        async send() {},
        async receive() {},
        async close() {},
      };

      const encryptedFile = await idManager.requestEncryptFile(mockChannel, {
        name: file.name,
        type: file.type,
        arrayBuffer: Buffer.from(file.arrayBuffer),
      });

      if (encryptedFile) {
        setResult({
          type: "encrypted",
          file: encryptedFile,
          nonce: encryptedFile.nonce,
        });
      } else {
        setError("Encryption failed");
      }
    } catch (err) {
      console.error("Error encrypting file:", err);
      setError("Failed to encrypt file: " + err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleDecryptFile() {
    if (!file || !idManager) {
      setError("Please select an encrypted file first");
      return;
    }

    try {
      setLoading(true);
      setError("");

      // The file needs to have a nonce property for decryption
      if (!file.nonce) {
        // Try to parse the nonce from the filename if it has it
        const noncePart = file.name?.match(/nonce-([a-f0-9]+)/i);
        if (noncePart && noncePart[1]) {
          file.nonce = noncePart[1];
        } else {
          setError("This file doesn't have encryption nonce information. Cannot decrypt.");
          setLoading(false);
          return;
        }
      }

      // Create a mock channel that our ID will communicate with itself
      const mockChannel = {
        async send() {},
        async receive() {},
        async close() {},
      };

      const decryptedFile = await idManager.requestDecryptFile(mockChannel, {
        name: file.name,
        type: file.type || "application/octet-stream",
        arrayBuffer: Buffer.from(file.arrayBuffer),
        nonce: file.nonce,
      });

      if (decryptedFile) {
        setResult({
          type: "decrypted",
          file: decryptedFile,
        });
      } else {
        setError("Decryption failed. Make sure this file was encrypted with your VaultysID.");
      }
    } catch (err) {
      console.error("Error decrypting file:", err);
      setError("Failed to decrypt file: " + err.message);
    } finally {
      setLoading(false);
    }
  }

  function downloadResult() {
    if (!result) return;

    const blob = new Blob([result.file.arrayBuffer], { type: result.file.type || "application/octet-stream" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;

    // Create appropriate filename
    let filename = result.file.name || "file";
    if (result.type === "encrypted" && !filename.includes("encrypted")) {
      filename = `encrypted-${filename}-nonce-${result.nonce}`;
    } else if (result.type === "decrypted" && filename.includes("encrypted")) {
      filename = filename.replace("encrypted-", "").replace(/-nonce-[a-f0-9]+/i, "");
    }

    a.download = filename;
    document.body.appendChild(a);
    a.click();

    // Clean up
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  }

  if (loading) {
    return (
      <div className="container">
        <h1>VaultysID File Encryption</h1>
        <div className="loading">
          <div className="spinner"></div>
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  if (isCreating) {
    return (
      <div className="container">
        <h1>VaultysID File Encryption</h1>
        <div className="setup-container">
          <h2>Let's set up your VaultysID</h2>
          <p>Choose how you want to create your identity:</p>

          <div className="button-container">
            <button onClick={createWebAuthnId} className="primary-button">
              Use WebAuthn/Passkey (Recommended)
            </button>
            <button onClick={createSoftwareId} className="secondary-button">
              Use Software Key
            </button>
          </div>

          <p className="info-text">
            <strong>WebAuthn/Passkey:</strong> Uses your device's security features for strongest protection.
            <br />
            <strong>Software Key:</strong> Stored in your browser's localStorage.
          </p>

          {error && <div className="error-message">{error}</div>}
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <h1>VaultysID File Encryption</h1>

      <div className="identity-info">
        <div>
          <strong>Your ID:</strong> {idManager?.vaultysId?.fingerprint || "Unknown"}
          <br />
          <strong>Type:</strong> {idManager?.isHardware() ? "Hardware/WebAuthn" : "Software"}
        </div>
        <button onClick={resetIdentity} className="reset-button">
          Reset ID
        </button>
      </div>

      <div className="tabs">
        <button className={activeTab === "encrypt" ? "active" : ""} onClick={() => setActiveTab("encrypt")}>
          Encrypt File
        </button>
        <button className={activeTab === "decrypt" ? "active" : ""} onClick={() => setActiveTab("decrypt")}>
          Decrypt File
        </button>
      </div>

      <div className="tab-content">
        <div className="file-selection">
          <input type="file" onChange={handleFileChange} ref={fileInputRef} style={{ display: "none" }} />
          <button onClick={() => fileInputRef.current.click()} className="file-button">
            Select File
          </button>
          {file && <div className="file-info">Selected: {file.name}</div>}
        </div>

        {activeTab === "encrypt" ? (
          <button onClick={handleEncryptFile} disabled={!file || loading} className="action-button">
            Encrypt File
          </button>
        ) : (
          <button onClick={handleDecryptFile} disabled={!file || loading} className="action-button">
            Decrypt File
          </button>
        )}

        {error && <div className="error-message">{error}</div>}

        {result && (
          <div className="result-container">
            <h3>{result.type === "encrypted" ? "File Encrypted Successfully" : "File Decrypted Successfully"}</h3>
            <button onClick={downloadResult} className="download-button">
              Download {result.type === "encrypted" ? "Encrypted" : "Decrypted"} File
            </button>
            {result.type === "encrypted" && (
              <div className="nonce-info">
                <p>
                  <strong>Nonce:</strong> {result.nonce}
                </p>
                <p className="help-text">The nonce is included in the filename for decryption. Keep it with the file.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
