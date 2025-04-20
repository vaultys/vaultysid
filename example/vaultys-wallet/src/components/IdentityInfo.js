export default function IdentityInfo({ idManager, onReset }) {
  return (
    <div className="bg-white rounded-lg shadow-sm p-4 mb-6 flex justify-between items-center flex-col sm:flex-row">
      <div>
        <p className="mb-1">
          <span className="font-medium">Your ID:</span> {idManager?.vaultysId?.fingerprint || "Unknown"}
        </p>
        <p>
          <span className="font-medium">Security:</span> {idManager?.isHardware() ? "Hardware/WebAuthn" : "Software Key"}
        </p>
      </div>
      <button onClick={onReset} className="mt-3 sm:mt-0 px-3 py-1.5 text-sm border border-gray-300 rounded hover:bg-gray-100 hover:text-red-600 transition-colors">
        Reset Wallet
      </button>
    </div>
  );
}
