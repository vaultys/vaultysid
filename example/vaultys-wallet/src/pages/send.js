import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import IdentityInfo from "../components/IdentityInfo";
import TransactionForm from "../components/TransactionForm";
import { initVaultysId, resetIdentity } from "../lib/identityHelper";
import { getBalance } from "../lib/walletHelper";

export default function Send() {
  const [idManager, setIdManager] = useState(null);
  const [walletInfo, setWalletInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [currentAddress, setCurrentAddress] = useState("");
  const [balance, setBalance] = useState({ confirmed: 0, unconfirmed: 0, total: 0 });
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

        // Load current address and balance
        if (storedWalletInfo.addresses && storedWalletInfo.addresses.length > 0) {
          // Use the last generated address
          const address = storedWalletInfo.addresses[storedWalletInfo.addresses.length - 1].address;
          setCurrentAddress(address);

          // Fetch balance
          const balanceData = await getBalance(address);
          setBalance(balanceData);
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

  const handleResetWallet = () => {
    if (confirm("Are you sure you want to reset your wallet? This will delete all your wallet data and cannot be undone.")) {
      resetIdentity();
      localStorage.removeItem("walletInfo");
      router.push("/");
    }
  };

  if (loading) {
    return (
      <Layout title="Send Bitcoin">
        <LoadingSpinner message="Loading..." />
      </Layout>
    );
  }

  return (
    <Layout title="Send Bitcoin">
      <IdentityInfo idManager={idManager} onReset={handleResetWallet} />
      <TransactionForm idManager={idManager} sourceAddress={currentAddress} balance={balance} />
      <div className="card mt-6">
        <h3 className="text-lg font-medium mb-4">Transaction Tips</h3>

        <div className="text-gray-600 space-y-3">
          <p>
            <strong>⚠️ Important:</strong> Bitcoin transactions cannot be reversed. Always double-check the recipient address before sending.
          </p>
          <p>Network fees are required for transactions to be confirmed. Higher fees typically result in faster confirmations.</p>
          <p>For security reasons, sensitive operations require authorization through your VaultysID.</p>
        </div>
      </div>
      {error && <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-md">{error}</div>}
      <div className="py-16"></div> {/* Space for bottom nav */}
    </Layout>
  );
}
