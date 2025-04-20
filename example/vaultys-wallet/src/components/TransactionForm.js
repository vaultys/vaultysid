import { useState } from "react";
import { signTransaction, broadcastTransaction } from "../lib/walletHelper";
import QRCodeModal from "./QRCodeModal";

export default function TransactionForm({ idManager, sourceAddress, balance }) {
  const [destinationAddress, setDestinationAddress] = useState("");
  const [amount, setAmount] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [channelInfo, setChannelInfo] = useState(null);
  const [processingStatus, setProcessingStatus] = useState("");
  const [txData, setTxData] = useState(null);

  const handleSend = async (e) => {
    e.preventDefault();

    if (!destinationAddress || !amount) {
      setError("Please fill in all fields");
      return;
    }

    if (isNaN(amount) || parseFloat(amount) <= 0) {
      setError("Please enter a valid amount");
      return;
    }

    if (parseFloat(amount) > balance.total) {
      setError("Insufficient funds");
      return;
    }

    try {
      setLoading(true);
      setError("");
      setSuccess("");

      // Prepare transaction data (simplified for this example)
      // In a real app, you would fetch UTXOs from an API
      const btcAmount = parseFloat(amount);
      const satoshis = Math.floor(btcAmount * 100000000);

      // Dummy transaction data for demonstration
      // In a real app, you would get this from an API
      const mockTxData = {
        inputTxId: "0000000000000000000000000000000000000000000000000000000000000000", // This would be real in production
        inputVout: 0,
        inputAmount: satoshis + 1000, // Adding fee
        sourceAddress: sourceAddress,
        destinationAddress: destinationAddress,
        amount: satoshis,
        changeAmount: 1000, // Change amount (simplified)
      };

      setTxData(mockTxData);

      // Open modal for remote PRF
      setIsModalOpen(true);
      setProcessingStatus("Setting up secure channel for transaction signing...");

      // In a real implementation, you would set up the channel here
      // and then process the transaction when connected
      // For now, we'll simulate a connection after a delay
      setTimeout(() => {
        setProcessingStatus("Connected to remote device. Processing transaction...");

        // Simulate signing and broadcasting
        setTimeout(async () => {
          try {
            // In a real app, this would be the actual signing process
            const { txHex, txId } = await signTransaction(idManager, mockTxData, 0);

            // In a real app, this would broadcast to the network
            // const broadcastResult = await broadcastTransaction(txHex);

            setSuccess(`Transaction sent! Transaction ID: ${txId}`);
            setProcessingStatus("Transaction signed successfully!");

            // Close modal after a delay
            setTimeout(() => {
              setIsModalOpen(false);
              setDestinationAddress("");
              setAmount("");
            }, 2000);
          } catch (error) {
            setError(`Failed to sign transaction: ${error.message}`);
            setIsModalOpen(false);
          }
        }, 2000);
      }, 1500);
    } catch (error) {
      console.error("Send transaction error:", error);
      setError(`Failed to send: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="card">
        <h3 className="text-lg font-medium mb-4">Send Bitcoin</h3>

        <form onSubmit={handleSend}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-1">Recipient Address</label>
            <input type="text" value={destinationAddress} onChange={(e) => setDestinationAddress(e.target.value)} placeholder="Enter Bitcoin address" className="input-field" disabled={loading} />
          </div>

          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-1">Amount (BTC)</label>
            <div className="relative">
              <input type="text" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0.00000000" className="input-field pr-16" disabled={loading} />
              <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                <span className="text-gray-500">BTC</span>
              </div>
            </div>
            <div className="flex justify-between mt-1">
              <span className="text-xs text-gray-500">Available: {balance?.total.toFixed(8)} BTC</span>
              <button type="button" onClick={() => setAmount(balance?.total.toFixed(8))} className="text-xs text-orange-500 hover:text-orange-600">
                Send Max
              </button>
            </div>
          </div>

          <button type="submit" disabled={loading} className={`w-full py-3 rounded-lg font-medium ${loading ? "bg-gray-300 text-gray-500 cursor-not-allowed" : "bg-orange-500 hover:bg-orange-600 text-white"} transition-colors`}>
            {loading ? "Processing..." : "Send Bitcoin"}
          </button>
        </form>

        {error && <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-md">{error}</div>}

        {success && <div className="mt-4 p-3 bg-green-50 text-green-700 rounded-md">{success}</div>}
      </div>

      <QRCodeModal
        isOpen={isModalOpen}
        channelInfo="bitcoin:?channel=mock" // This would be real channel info in production
        processingStatus={processingStatus}
        onCancel={() => setIsModalOpen(false)}
        actionType="Sign Transaction"
      />
    </>
  );
}
