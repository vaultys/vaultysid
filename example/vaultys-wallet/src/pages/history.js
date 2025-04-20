import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import IdentityInfo from "../components/IdentityInfo";
import TransactionHistory from "../components/TransactionHistory";
import { initVaultysId, resetIdentity } from "../lib/identityHelper";

export default function History() {
  const [idManager, setIdManager] = useState(null);
  const [walletInfo, setWalletInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [currentAddress, setCurrentAddress] = useState("");
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [error, setError] = useState("");
  const router = useRouter();

  useEffect(() => {
    async function loadWallet() {
      try {
        // Check if wallet is set up
        const walletInfoStr = localStorage.getItem("walletInfo");
        const storedWalletInfo = walletInfoStr ? JSON.parse(walletInfoStr) : null;

        if (!storedWalletInfo || !storedWalletInfo.initialized) {
          // Wallet not initialized, redirect to setup
          router.push("/setup");
          return;
        }

        setWalletInfo(storedWalletInfo);

        // Load identity
        const { idManager, isCreating } = await initVaultysId();

        if (isCreating || !idManager) {
          // No identity, redirect to home
          router.push("/");
          return;
        }

        setIdManager(idManager);

        // Load current address
        if (storedWalletInfo.addresses && storedWalletInfo.addresses.length > 0) {
          // Use the last generated address
          setCurrentAddress(storedWalletInfo.addresses[storedWalletInfo.addresses.length - 1].address);
        } else {
          // No addresses, redirect to wallet
          router.push("/wallet");
          return;
        }
      } catch (err) {
        console.error("Error loading wallet:", err);
        setError(`Failed to load wallet: ${err.message}`);
      } finally {
        setLoading(false);
      }
    }

    loadWallet();
  }, [router]);

  const handleRefresh = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  const handleResetWallet = () => {
    if (confirm("Are you sure you want to reset your wallet? This will delete all your wallet data and cannot be undone.")) {
      resetIdentity();
      localStorage.removeItem("walletInfo");
      router.push("/");
    }
  };

  if (loading) {
    return (
      <Layout title="Transaction History">
        <LoadingSpinner message="Loading..." />
      </Layout>
    );
  }

  return (
    <Layout title="Transaction History">
      <IdentityInfo idManager={idManager} onReset={handleResetWallet} />
      <TransactionHistory address={currentAddress} refreshTrigger={refreshTrigger} />
      <div className="mt-6 text-center">
        <button onClick={handleRefresh} className="text-orange-500 text-sm font-medium hover:text-orange-600">
          Refresh History
        </button>
      </div>
      {error && <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-md">{error}</div>}
      <div className="py-16"></div> {/* Space for bottom nav */}
    </Layout>
  );
}
