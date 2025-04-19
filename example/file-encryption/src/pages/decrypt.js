import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import IdentityInfo from "../components/IdentityInfo";
import FileSelector from "../components/FileSelector";
import TabNavigation from "../components/TabNavigation";
import QRCodeModal from "../components/QRCodeModal";
import ResultDisplay from "../components/ResultDisplay";
import { initVaultysId, resetIdentity, setupPeerJsChannel } from "../lib/vaultysIdHelper";
import { saveAs } from "file-saver";
import ConfirmationModal from "@/components/ConfirmationModal";

export default function DecryptPage() {
  const [idManager, setIdManager] = useState(null);
  const [loading, setLoading] = useState(true);
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isChannelOpen, setIsChannelOpen] = useState(false);
  const [channelInfo, setChannelInfo] = useState(null);
  const [processingStatus, setProcessingStatus] = useState("");
  const [channelRef, setChannelRef] = useState(null);
  const [decryptMethod, setDecryptMethod] = useState("local");
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);

  const router = useRouter();

  useEffect(() => {
    async function initialize() {
      try {
        setLoading(true);
        const { idManager, isCreating } = await initVaultysId();

        if (isCreating) {
          router.push("/");
          return;
        }

        setIdManager(idManager);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    initialize();
  }, [router]);

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

  function handleResetIdentity() {
    setIsResetModalOpen(true);
  }

  function confirmResetIdentity() {
    resetIdentity();
    setIsResetModalOpen(false);
    router.push("/");
  }

  function cancelResetIdentity() {
    setIsResetModalOpen(false);
  }

  async function handleDecryptFile() {
    if (!file || !idManager) {
      setError("Please select an encrypted file first");
      return;
    }

    try {
      setLoading(true);
      setError("");

      const encryptedContent = Buffer.from(file.arrayBuffer);

      if (encryptedContent.length < 32) {
        setError("This file is too small to be a valid encrypted file.");
        setLoading(false);
        return;
      }

      if (decryptMethod === "local") {
        const result = await idManager.decryptFile({
          name: file.name,
          type: file.type || "application/octet-stream",
          arrayBuffer: encryptedContent,
        });

        if (result) {
          setResult({
            type: "decrypted",
            file: result,
          });
          setProcessingStatus("File decrypted successfully!");
        } else {
          setError("Decryption failed. Make sure this file was encrypted with your VaultysID.");
        }
      } else {
        setProcessingStatus("Setting up secure channel...");

        // Setup channel for remote processing
        const { channel, channelUrl } = await setupPeerJsChannel(idManager);
        setChannelRef(channel);
        setChannelInfo(channelUrl);
        setIsChannelOpen(true);
        setProcessingStatus("Channel ready. Scan the QR code with your mobile device to continue.");
        setLoading(false);

        // Setup connection handler
        channel.onConnected(() => {
          setProcessingStatus("Connected to remote device. Processing file...");
        });

        // Wait for the remote processing to complete
        const result = await idManager.requestDecryptFile(channel, {
          name: file.name,
          type: file.type || "application/octet-stream",
          arrayBuffer: encryptedContent,
        });

        channel.close();

        if (result) {
          setResult({
            type: "decrypted",
            file: result,
          });
          setProcessingStatus("File decrypted successfully!");
        } else {
          setError("Decryption failed. Make sure this file was encrypted with your VaultysID.");
        }
      }
    } catch (err) {
      console.error("Error decrypting file:", err);
      setError("Failed to decrypt file: " + err.message);
    } finally {
      setLoading(false);
      setIsChannelOpen(false);
    }
  }

  function cancelChannelOperation() {
    if (channelRef) {
      channelRef.close();
    }
    setIsChannelOpen(false);
    setChannelInfo(null);
    setProcessingStatus("");
  }

  function downloadResult() {
    if (!result) return;

    // Create appropriate filename
    let filename = result.file.name || "file";
    if (result.type === "encrypted") {
      filename = `${filename}.enc`;
    } else if (result.type === "decrypted" && filename.endsWith(".enc")) {
      filename = filename.slice(0, -4);
    }

    // Create blob with proper MIME type
    const blob = new Blob([result.file.arrayBuffer]);

    // Use FileSaver to handle the download
    saveAs(blob, filename);
  }

  if (loading && !isChannelOpen) {
    return (
      <Layout>
        <LoadingSpinner />
      </Layout>
    );
  }

  return (
    <Layout>
      <IdentityInfo idManager={idManager} onReset={handleResetIdentity} />

      <TabNavigation />

      <div className="bg-white rounded-lg shadow-md p-6">
        <FileSelector file={file} onFileChange={handleFileChange} />
        <div className="mt-4 mb-4">
          <div className="flex justify-center space-x-4">
            <label className="inline-flex items-center">
              <input type="radio" className="form-radio" name="decryptMethod" value="local" checked={decryptMethod === "local"} onChange={() => setDecryptMethod("local")} />
              <span className="ml-2">in browser</span>
            </label>
            <label className="inline-flex items-center">
              <input type="radio" className="form-radio" name="decryptMethod" value="remote" checked={decryptMethod === "remote"} onChange={() => setDecryptMethod("remote")} />
              <span className="ml-2">with QR code</span>
            </label>
          </div>
        </div>
        <button onClick={handleDecryptFile} disabled={!file || loading} className={`w-full py-3 rounded-lg font-semibold ${!file || loading ? "bg-gray-300 cursor-not-allowed text-gray-500" : "cursor-pointer bg-indigo-600 hover:bg-indigo-700 text-white"} transition-colors`}>
          Decrypt File
        </button>

        {error && <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-md">{error}</div>}

        <ResultDisplay result={result} onDownload={downloadResult} />
      </div>

      <QRCodeModal isOpen={isChannelOpen} channelInfo={channelInfo} processingStatus={processingStatus} onCancel={cancelChannelOperation} actionType="decrypt" />
      <ConfirmationModal isOpen={isResetModalOpen} title="Reset Identity" message="Are you sure you want to reset your VaultysID? This action cannot be undone." onConfirm={confirmResetIdentity} onCancel={cancelResetIdentity} />
    </Layout>
  );
}
