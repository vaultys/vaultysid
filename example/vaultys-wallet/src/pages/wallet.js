import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import IdentityInfo from "../components/IdentityInfo";
import Balance from "../components/Balance";
import { initVaultysId, resetIdentity } from "../lib/identityHelper";
import { generateAddress } from "../lib/walletHelper";

export default function Wallet() {
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

        // Load current address or generate one if none exists
        if (storedWalletInfo.addresses && storedWalletInfo.addresses.length > 0) {
          // Use the last generated address
          setCurrentAddress(storedWalletInfo.addresses[storedWalletInfo.addresses.length - 1].address);
        } else {
          // Generate a first address
          const { address } = await generateAddress(idManager, 0, false);
          setCurrentAddress(address);

          // Re-fetch wallet info after address generation
          const updatedWalletInfoStr = localStorage.getItem("walletInfo");
          const updatedWalletInfo = updatedWalletInfoStr ? JSON.parse(updatedWalletInfoStr) : null;
          setWalletInfo(updatedWalletInfo);
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
      <Layout title="Your Wallet">
        <LoadingSpinner message="Loading your wallet..." />
      </Layout>
    );
  }

  return (
    <Layout title="Your Wallet">
      <IdentityInfo idManager={idManager} onReset={handleResetWallet} />
      <Balance address={currentAddress} refreshTrigger={refreshTrigger} />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div onClick={() => router.push("/receive")} className="card text-center cursor-pointer hover:shadow-md transition-shadow">
          <div className="flex flex-col items-center py-4">
            <div className="w-12 h-12 rounded-full bg-green-100 flex items-center justify-center mb-2">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6 text-green-600">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />
              </svg>
            </div>
            <h3 className="font-medium">Receive Bitcoin</h3>
          </div>
        </div>

        <div onClick={() => router.push("/send")} className="card text-center cursor-pointer hover:shadow-md transition-shadow">
          <div className="flex flex-col items-center py-4">
            <div className="w-12 h-12 rounded-full bg-orange-100 flex items-center justify-center mb-2">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6 text-orange-600">
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 12 3.269 3.125A59.769 59.769 0 0 1 21.485 12 59.768 59.768 0 0 1 3.27 20.875L5.999 12Zm0 0h7.5" />
              </svg>
            </div>
            <h3 className="font-medium">Send Bitcoin</h3>
          </div>
        </div>
      </div>
      <div className="mt-6">
        <div onClick={() => router.push("/history")} className="card cursor-pointer hover:shadow-md transition-shadow">
          <div className="flex items-center justify-between py-2">
            <div className="flex items-center">
              <div className="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center mr-3">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5 text-gray-600">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                </svg>
              </div>
              <h3 className="font-medium">Transaction History</h3>
            </div>
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5 text-gray-400">
              <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
            </svg>
          </div>
        </div>
      </div>
      {error && <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-md">{error}</div>}
      <div className="mt-6 text-center">
        <button onClick={handleRefresh} className="text-orange-500 text-sm font-medium hover:text-orange-600">
          Refresh Wallet
        </button>
      </div>
      <div className="py-16"></div> {/* Space for bottom nav */}
    </Layout>
  );
}
