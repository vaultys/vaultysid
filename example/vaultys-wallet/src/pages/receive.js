import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import IdentityInfo from "../components/IdentityInfo";
import AddressDisplay from "../components/AddressDisplay";
import { initVaultysId, resetIdentity } from "../lib/identityHelper";
import { generateAddress } from "../lib/walletHelper";

export default function Receive() {
  const [idManager, setIdManager] = useState(null);
  const [walletInfo, setWalletInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [currentAddress, setCurrentAddress] = useState("");
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

  const handleAddressChange = (address) => {
    setCurrentAddress(address);

    // Re-fetch wallet info after address generation
    const updatedWalletInfoStr = localStorage.getItem("walletInfo");
    const updatedWalletInfo = updatedWalletInfoStr ? JSON.parse(updatedWalletInfoStr) : null;
    setWalletInfo(updatedWalletInfo);
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
      <Layout title="Receive Bitcoin">
        <LoadingSpinner message="Loading..." />
      </Layout>
    );
  }

  return (
    <Layout title="Receive Bitcoin">
      <IdentityInfo idManager={idManager} onReset={handleResetWallet} />
      <AddressDisplay idManager={idManager} currentAddress={currentAddress} onAddressChange={handleAddressChange} walletInfo={walletInfo} />
      <div className="card">
        <h3 className="text-lg font-medium mb-4">Address Usage Tips</h3>

        <div className="text-gray-600 space-y-3">
          <p>
            <strong>⚠️ Important:</strong> For better privacy, consider generating a new address for each transaction.
          </p>
          <p>Share your address with anyone who wants to send you Bitcoin. Your address is public information and can be safely shared.</p>
          <p>Always double-check the address when sharing it to avoid typos. Bitcoin transactions cannot be reversed.</p>
        </div>
      </div>
      {error && <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-md">{error}</div>}
      <div className="py-16"></div> {/* Space for bottom nav */}
    </Layout>
  );
}
