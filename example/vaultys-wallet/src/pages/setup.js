import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import QRCodeModal from "../components/QRCodeModal";
import { initVaultysId } from "../lib/identityHelper";
import { initializeWallet } from "../lib/walletHelper";

export default function Setup() {
  const [idManager, setIdManager] = useState(null);
  const [loading, setLoading] = useState(true);
  const [initializing, setInitializing] = useState(false);
  const [error, setError] = useState("");
  const [isQRModalOpen, setIsQRModalOpen] = useState(false);
  const [channelInfo, setChannelInfo] = useState("");
  const [processingStatus, setProcessingStatus] = useState("");
  const router = useRouter();

  useEffect(() => {
    async function checkIdentity() {
      try {
        // Check if wallet is already set up
        const walletInfoStr = localStorage.getItem("walletInfo");
        const walletInfo = walletInfoStr ? JSON.parse(walletInfoStr) : null;

        if (walletInfo && walletInfo.initialized) {
          // Wallet exists, redirect to wallet page
          router.push("/wallet");
          return;
        }

        // Load identity
        const { idManager, isCreating } = await initVaultysId();

        if (isCreating || !idManager) {
          // No identity, redirect to home
          router.push("/");
          return;
        }

        setIdManager(idManager);
      } catch (err) {
        console.error("Error checking identity:", err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    // Only run on client side
    if (typeof window !== "undefined") {
      checkIdentity();
    }
  }, [router]);

  const handleInitializeWallet = async (useRemotePRF) => {
    try {
      setInitializing(true);
      setError("");

      if (useRemotePRF) {
        // We'll need to show the QR code for remote PRF
        setIsQRModalOpen(true);
        setProcessingStatus("Setting up secure channel for wallet initialization...");

        // The QR code and channel setup is handled inside initializeWallet
        // We just need to subscribe to its events
        const handleChannelSetup = (info) => {
          setChannelInfo(info);
        };

        const handleStatusUpdate = (status) => {
          setProcessingStatus(status);
        };

        // Add event listeners (this is a simplified example)
        window.addEventListener("channel-setup", handleChannelSetup);
        window.addEventListener("processing-status", handleStatusUpdate);

        // Initialize wallet with remote PRF
        await initializeWallet(idManager, true, {
          onChannelSetup: (info) => {
            setChannelInfo(info);
          },
          onStatusUpdate: (status) => {
            setProcessingStatus(status);
          },
        });

        // Remove event listeners
        window.removeEventListener("channel-setup", handleChannelSetup);
        window.removeEventListener("processing-status", handleStatusUpdate);

        setIsQRModalOpen(false);
      } else {
        // Initialize wallet with local PRF
        await initializeWallet(idManager, false);
      }

      // Redirect to wallet page
      router.push("/wallet");
    } catch (err) {
      console.error("Error initializing wallet:", err);
      setError(`Failed to initialize wallet: ${err.message}`);
      setInitializing(false);
      setIsQRModalOpen(false);
    }
  };

  const handleCancelOperation = () => {
    setIsQRModalOpen(false);
    setInitializing(false);
  };

  if (loading || (initializing && !isQRModalOpen)) {
    return (
      <Layout title="Setting Up Your Wallet">
        <LoadingSpinner message={initializing ? "Initializing your wallet..." : "Loading..."} />
      </Layout>
    );
  }

  return (
    <Layout title="Complete Wallet Setup">
      <div className="max-w-md mx-auto">
        <div className="card text-center">
          <div className="bg-orange-100 text-orange-600 p-5 rounded-full inline-block mb-4">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-10 h-10">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />
            </svg>
          </div>

          <h3 className="text-xl font-semibold mb-2">Choose Your Security Level</h3>
          <p className="text-gray-600 mb-6">Your identity has been created. Now, select how you'd like to generate your wallet keys:</p>

          <div className="space-y-4 mb-6">
            <button onClick={() => handleInitializeWallet(true)} className="w-full btn-primary py-3">
              Use Remote PRF (Most Secure)
            </button>
            <button onClick={() => handleInitializeWallet(false)} className="w-full btn-secondary py-3">
              Use Local PRF (Faster)
            </button>
          </div>

          <div className="text-sm text-gray-600 text-left">
            <p className="mb-1">
              <strong>Remote PRF:</strong> Requires a VaultysID-compatible mobile device for key derivation, providing better security by keeping your private keys off this device.
            </p>
            <p>
              <strong>Local PRF:</strong> Generates keys locally in your browser, which is faster but potentially less secure.
            </p>
          </div>

          {error && <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-md">{error}</div>}
        </div>
      </div>

      <QRCodeModal isOpen={isQRModalOpen} channelInfo={channelInfo} processingStatus={processingStatus} onCancel={handleCancelOperation} actionType="Initialize Wallet" />
    </Layout>
  );
}
