import { useState, useEffect } from "react";
import { getTransactionHistory } from "../lib/walletHelper";

export default function TransactionHistory({ address, refreshTrigger }) {
  const [transactions, setTransactions] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchTransactions() {
      if (!address) return;

      setLoading(true);
      try {
        const txs = await getTransactionHistory(address);
        setTransactions(txs);
      } catch (error) {
        console.error("Failed to fetch transactions:", error);
      } finally {
        setLoading(false);
      }
    }

    fetchTransactions();
  }, [address, refreshTrigger]);

  if (loading) {
    return (
      <div className="card">
        <h3 className="text-lg font-medium mb-4">Transaction History</h3>
        <div className="py-8 flex justify-center">
          <div className="w-8 h-8 border-2 border-gray-200 border-t-orange-500 rounded-full animate-spin"></div>
        </div>
      </div>
    );
  }

  if (transactions.length === 0) {
    return (
      <div className="card">
        <h3 className="text-lg font-medium mb-4">Transaction History</h3>
        <div className="py-8 text-center text-gray-500">No transactions found for this address</div>
      </div>
    );
  }

  return (
    <div className="card">
      <h3 className="text-lg font-medium mb-4">Transaction History</h3>

      <div className="divide-y divide-gray-100">
        {transactions.map((tx) => (
          <div key={tx.txid} className="py-4">
            <div className="flex justify-between items-start">
              <div>
                <div className="flex items-center">
                  {tx.type === "incoming" ? (
                    <span className="w-6 h-6 rounded-full bg-green-100 text-green-600 flex items-center justify-center mr-2">
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-11a1 1 0 10-2 0v3.586L7.707 9.293a1 1 0 00-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L11 10.586V7z" clipRule="evenodd" />
                      </svg>
                    </span>
                  ) : (
                    <span className="w-6 h-6 rounded-full bg-red-100 text-red-600 flex items-center justify-center mr-2">
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-11a1 1 0 10-2 0v3.586L7.707 9.293a1 1 0 00-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L11 10.586V7z" clipRule="evenodd" />
                      </svg>
                    </span>
                  )}
                  <span className="font-medium">{tx.type === "incoming" ? "Received" : tx.type === "outgoing" ? "Sent" : "Self Transfer"}</span>
                </div>
                <div className="text-xs text-gray-500 mt-1">{tx.confirmed ? (tx.time ? new Date(tx.time).toLocaleString() : "Confirmed") : "Pending"}</div>
              </div>

              <div className="text-right">
                <div className={`font-medium ${tx.value > 0 ? "text-green-600" : "text-red-600"}`}>
                  {tx.value > 0 ? "+" : ""}
                  {tx.value.toFixed(8)} BTC
                </div>
                <div className="text-xs text-gray-500 mt-1">
                  <a href={`https://blockstream.info/testnet/tx/${tx.txid}`} target="_blank" rel="noopener noreferrer" className="hover:text-orange-500">
                    View on Explorer ↗
                  </a>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
