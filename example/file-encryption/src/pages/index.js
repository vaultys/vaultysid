import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import { initVaultysId, createWebAuthnId, createSoftwareId } from "../lib/vaultysIdHelper";

export default function Home() {
  const [idManager, setIdManager] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isCreating, setIsCreating] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();

  useEffect(() => {
    async function initialize() {
      try {
        setLoading(true);
        const { idManager, isCreating } = await initVaultysId();
        setIdManager(idManager);
        setIsCreating(isCreating);

        if (idManager) {
          router.push("/encrypt");
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    initialize();
  }, [router]);

  async function handleCreateWebAuthnId() {
    try {
      setLoading(true);
      setError("");
      const manager = await createWebAuthnId();
      setIdManager(manager);
      router.push("/encrypt");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleCreateSoftwareId() {
    try {
      setLoading(true);
      setError("");
      const manager = await createSoftwareId();
      setIdManager(manager);
      router.push("/encrypt");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <Layout>
        <LoadingSpinner />
      </Layout>
    );
  }

  if (isCreating) {
    return (
      <Layout>
        <div className="bg-white rounded-lg shadow-md p-8 text-center">
          <h2 className="text-2xl font-semibold mb-4">Let&apos;s set up your VaultysID</h2>
          <p className="mb-6">Choose how you want to create your identity:</p>

          <div className="flex flex-col gap-4 mb-6">
            <button onClick={handleCreateWebAuthnId} className="py-3 px-6 bg-indigo-600 text-white font-semibold rounded-lg hover:bg-indigo-700 transition-colors">
              Use WebAuthn/Passkey (Recommended)
            </button>
            <button onClick={handleCreateSoftwareId} className="py-3 px-6 bg-white text-indigo-600 font-semibold rounded-lg border border-indigo-600 hover:bg-gray-50 transition-colors">
              Use Software Key
            </button>
          </div>

          <div className="text-sm text-gray-600 leading-relaxed">
            <p className="mb-1">
              <strong>WebAuthn/Passkey:</strong> Uses your device&apos;s security features for strongest protection.
            </p>
            <p>
              <strong>Software Key:</strong> Stored in your browser&apos;s localStorage.
            </p>
          </div>

          {error && <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-md">{error}</div>}
        </div>
      </Layout>
    );
  }

  // If we have an idManager but haven't redirected yet
  return (
    <Layout>
      <LoadingSpinner message="Redirecting..." />
    </Layout>
  );
}
