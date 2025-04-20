import { useState } from "react";
import { createWebAuthnId, createSoftwareId } from "../lib/identityHelper";
import LoadingSpinner from "./LoadingSpinner";

export default function WalletSetup({ onSetupComplete }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleCreateWebAuthnId = async () => {
    try {
      setLoading(true);
      setError("");
      const manager = await createWebAuthnId();
      onSetupComplete(manager);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateSoftwareId = async () => {
    try {
      setLoading(true);
      setError("");
      const manager = await createSoftwareId();
      onSetupComplete(manager);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <LoadingSpinner message="Setting up your wallet..." />;
  }

  return (
    <div className="card max-w-md mx-auto text-center">
      <h3 className="text-xl font-semibold mb-4">Set Up Your Bitcoin Wallet</h3>
      <p className="text-gray-600 mb-6">Choose how you want to secure your wallet:</p>

      <div className="space-y-4 mb-6">
        <button onClick={handleCreateWebAuthnId} className="w-full btn-primary py-3">
          Use WebAuthn/Passkey (Recommended)
        </button>
        <button onClick={handleCreateSoftwareId} className="w-full btn-secondary py-3">
          Use Software Key
        </button>
      </div>

      <div className="text-sm text-gray-600">
        <p className="mb-1">
          <strong>WebAuthn/Passkey:</strong> Uses your device's security features for strongest protection.
        </p>
        <p>
          <strong>Software Key:</strong> Stored in your browser's localStorage.
        </p>
      </div>

      {error && <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-md">{error}</div>}
    </div>
  );
}
