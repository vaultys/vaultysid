import { useState, useEffect, useRef } from "react";
import QRCode from "qrcode";
import { generateAddress } from "../lib/walletHelper";

export default function AddressDisplay({ idManager, currentAddress, onAddressChange, walletInfo }) {
  const [loading, setLoading] = useState(false);
  const [copiedMessage, setCopiedMessage] = useState("");
  const qrCodeRef = useRef(null);

  // Generate QR code when address changes
  useEffect(() => {
    if (currentAddress && qrCodeRef.current) {
      QRCode.toCanvas(qrCodeRef.current, `bitcoin:${currentAddress}`, {
        width: 200,
        margin: 1,
        color: {
          dark: "#000000",
          light: "#ffffff",
        },
      }).catch((err) => {
        console.error("Error generating QR code:", err);
      });
    }
  }, [currentAddress]);

  const handleGenerateNewAddress = async () => {
    try {
      setLoading(true);
      const newIndex = (walletInfo.lastAddressIndex || 0) + 1;
      const { address } = await generateAddress(idManager, newIndex);
      onAddressChange(address);
    } catch (error) {
      console.error("Failed to generate new address:", error);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(currentAddress).then(
      () => {
        setCopiedMessage("Address copied!");
        setTimeout(() => setCopiedMessage(""), 2000);
      },
      (err) => console.error("Could not copy address: ", err),
    );
  };

  return (
    <div className="card mb-6">
      <h3 className="text-lg font-medium mb-4">Receive Bitcoin</h3>

      <div className="bg-gray-50 p-4 rounded-lg mb-4">
        <div className="flex justify-center mb-4">
          {currentAddress ? (
            <div className="bg-white p-2 rounded-lg">
              <canvas ref={qrCodeRef} width="200" height="200" className="mx-auto"></canvas>
            </div>
          ) : (
            <div className="w-48 h-48 bg-gray-200 rounded-lg flex items-center justify-center">
              <span className="text-gray-400">No address available</span>
            </div>
          )}
        </div>

        {currentAddress && (
          <div className="relative">
            <div className="font-mono text-sm break-all p-3 bg-white border border-gray-200 rounded-lg">{currentAddress}</div>
            <button onClick={copyToClipboard} className="absolute right-2 top-2 p-1 text-gray-500 hover:text-orange-500" title="Copy address">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
              </svg>
            </button>
            {copiedMessage && <div className="absolute right-0 top-12 bg-gray-800 text-white px-2 py-1 rounded text-xs">{copiedMessage}</div>}
          </div>
        )}
      </div>

      <button onClick={handleGenerateNewAddress} disabled={loading} className={`w-full py-2 rounded-lg font-medium ${loading ? "bg-gray-300 text-gray-500 cursor-not-allowed" : "bg-orange-500 hover:bg-orange-600 text-white"} transition-colors`}>
        {loading ? "Generating..." : "Generate New Address"}
      </button>
    </div>
  );
}
