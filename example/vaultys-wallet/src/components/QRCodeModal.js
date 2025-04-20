import { useEffect, useRef } from "react";
import QRCode from "qrcode";

export default function QRCodeModal({ isOpen, channelInfo, processingStatus, onCancel, actionType }) {
  const qrcodeRef = useRef(null);

  useEffect(() => {
    if (isOpen && channelInfo && qrcodeRef.current) {
      QRCode.toCanvas(qrcodeRef.current, channelInfo, { width: 256 });
    }
  }, [isOpen, channelInfo]);

  if (!isOpen) return null;

  const isConnected = processingStatus.includes("Connected");
  const isComplete = processingStatus.includes("success");

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-white rounded-2xl w-[90%] max-w-2xl max-h-[90vh] overflow-auto shadow-xl animate-[slideIn_0.3s_ease-out]">
        <div className="flex justify-between items-center px-6 py-5 border-b border-gray-200">
          <h2 className="text-xl font-semibold text-gray-800">{actionType || "Secure Operation"}</h2>
          <div className={`py-1.5 px-3 rounded-full text-sm font-medium flex items-center ${isConnected ? "bg-green-100 text-green-800" : "bg-gray-200 text-gray-700"}`}>
            <span className={`w-2 h-2 rounded-full mr-2 ${isConnected ? "bg-green-500 shadow-[0_0_0_2px_rgba(16,185,129,0.3)] animate-pulse" : "bg-gray-500"}`}></span>
            {isConnected ? "Connected" : "Waiting for connection..."}
          </div>
        </div>

        <div className="p-6 md:flex md:items-start md:gap-6">
          <div className="md:flex-shrink-0 flex justify-center mb-6 md:mb-0">
            <div className="p-5 bg-white rounded-xl shadow-sm">
              <canvas ref={qrcodeRef} width="256" height="256" className="rounded"></canvas>
            </div>
          </div>

          <div className="flex-1 space-y-4">
            <div className="flex items-center gap-4">
              <div className="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center font-semibold text-gray-600 flex-shrink-0">1</div>
              <p className="text-gray-600">Open the Bitcoin Wallet app on your phone</p>
            </div>
            <div className="flex items-center gap-4">
              <div className="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center font-semibold text-gray-600 flex-shrink-0">2</div>
              <p className="text-gray-600">Tap the scan button in the app</p>
            </div>
            <div className="flex items-center gap-4">
              <div className="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center font-semibold text-gray-600 flex-shrink-0">3</div>
              <p className="text-gray-600">Point your camera at this QR code</p>
            </div>
          </div>
        </div>

        <div className="px-6 py-4 border-t border-gray-200">
          <p className="text-gray-600 mb-3">{processingStatus}</p>
          <div className="h-1.5 bg-gray-100 rounded overflow-hidden">
            <div className={`h-full bg-orange-500 rounded transition-all duration-300 ${isConnected ? "w-2/3" : isComplete ? "w-full" : "w-1/5"}`}></div>
          </div>
        </div>

        <div className="px-6 py-4 border-t border-gray-200 flex justify-center">
          <button onClick={onCancel} className="py-2.5 px-5 bg-gray-100 text-gray-600 rounded-lg border border-gray-300 hover:bg-gray-200 transition-colors font-medium">
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
