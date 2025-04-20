import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import WalletSetup from "../components/WalletSetup";
import { initVaultysId } from "../lib/identityHelper";
import { initializeWallet } from "../lib/walletHelper";

export default function Home() {
  const [idManager, setIdManager] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const router = useRouter();

  useEffect(() => {
    async function checkWalletSetup() {
      try {
        setLoading(true);
        // Check if wallet is already set up
        const walletInfoStr = localStorage.getItem("walletInfo");
        const walletInfo = walletInfoStr ? JSON.parse(walletInfoStr) : null;

        if (walletInfo && walletInfo.initialized) {
          // Wallet exists, redirect to wallet page
          router.push("/wallet");
          return;
        }

        // Check if identity exists
        const { idManager, isCreating } = await initVaultysId();
        setIdManager(idManager);

        if (!isCreating && idManager) {
          // Identity exists but wallet not initialized
          router.push("/setup");
        }

        // Otherwise stay on this page to create identity
      } catch (err) {
        console.error("Error checking wallet setup:", err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    checkWalletSetup();
  }, [router]);

  const handleSetupComplete = async (manager) => {
    setIdManager(manager);
    router.push("/setup");
  };

  if (loading) {
    return (
      <Layout title="">
        <LoadingSpinner message="Loading your wallet..." />
      </Layout>
    );
  }

  return (
    <Layout title="Welcome to Bitcoin Wallet">
      <div className="max-w-md mx-auto">
        <div className="text-center mb-8">
          <div className="bg-orange-100 text-orange-600 p-5 rounded-full inline-block mb-4">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="w-12 h-12">
              <path d="M21 6.375c0 2.692-4.03 4.875-9 4.875S3 9.067 3 6.375 7.03 1.5 12 1.5s9 2.183 9 4.875Z" />
              <path d="M12 12.75c2.685 0 5.19-.586 7.078-1.609a8.283 8.283 0 0 0 1.897-1.384c.016.121.025.244.025.368C21 12.817 16.97 15 12 15s-9-2.183-9-4.875c0-.124.009-.247.025-.368a8.285 8.285 0 0 0 1.897 1.384C6.809 12.164 9.315 12.75 12 12.75Z" />
              <path d="M12 16.5c2.685 0 5.19-.586 7.078-1.609a8.282 8.282 0 0 0 1.897-1.384c.016.121.025.244.025.368 0 2.692-4.03 4.875-9 4.875s-9-2.183-9-4.875c0-.124.009-.247.025-.368a8.284 8.284 0 0 0 1.897 1.384C6.809 15.914 9.315 16.5 12 16.5Z" />
              <path d="M12 20.25c2.685 0 5.19-.586 7.078-1.609a8.282 8.282 0 0 0 1.897-1.384c.016.121.025.244.025.368 0 2.692-4.03 4.875-9 4.875s-9-2.183-9-4.875c0-.124.009-.247.025-.368a8.284 8.284 0 0 0 1.897 1.384C6.809 19.664 9.315 20.25 12 20.25Z" />
            </svg>
          </div>
          <h1 className="text-3xl font-bold text-center">Bitcoin Wallet</h1>
          <p className="text-gray-600 mt-2">Secure, simple Bitcoin wallet with identity protection</p>
        </div>

        <WalletSetup onSetupComplete={handleSetupComplete} />

        {error && <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-md">{error}</div>}
      </div>
    </Layout>
  );
}
