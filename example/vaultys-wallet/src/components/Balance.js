import { useState, useEffect } from "react";
import { getBalance } from "../lib/walletHelper";

export default function Balance({ address, refreshTrigger }) {
  const [balance, setBalance] = useState({ confirmed: 0, unconfirmed: 0, total: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchBalance() {
      if (!address) return;

      setLoading(true);
      try {
        const balanceData = await getBalance(address);
        setBalance(balanceData);
      } catch (error) {
        console.error("Failed to fetch balance:", error);
      } finally {
        setLoading(false);
      }
    }

    fetchBalance();
  }, [address, refreshTrigger]);

  return (
    <div className="card mb-6">
      <div className="flex justify-between items-center mb-2">
        <h3 className="text-lg font-medium">Your Balance</h3>
        {loading ? (
          <div className="w-5 h-5 border-2 border-gray-200 border-t-orange-500 rounded-full animate-spin"></div>
        ) : (
          <button onClick={() => setLoading(true)} className="text-orange-500 text-sm font-medium hover:text-orange-600">
            Refresh
          </button>
        )}
      </div>

      <div className="text-center py-4">
        <div className="text-3xl font-bold text-gray-800">{balance.total.toFixed(8)} BTC</div>
        {balance.unconfirmed > 0 && <div className="text-sm text-gray-500 mt-1">{balance.unconfirmed.toFixed(8)} BTC unconfirmed</div>}
      </div>

      <div className="mt-4 pt-4 border-t border-gray-100 text-center text-sm text-gray-500">
        <p>Using testnet Bitcoin for development</p>
      </div>
    </div>
  );
}
