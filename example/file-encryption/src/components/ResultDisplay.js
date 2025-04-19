export default function ResultDisplay({ result, onDownload }) {
  if (!result) return null;

  return (
    <div className="mt-8 pt-6 border-t border-gray-300">
      <h3 className="text-xl font-medium mb-4">{result.type === "encrypted" ? "File Encrypted Successfully" : "File Decrypted Successfully"}</h3>

      <button onClick={onDownload} className="cursor-pointer w-full py-3 bg-emerald-600 hover:bg-emerald-700 text-white font-medium rounded-lg transition-colors">
        Download {result.type === "encrypted" ? "Encrypted" : "Decrypted"} File
      </button>

      {result.type === "encrypted" && (
        <div className="mt-4 p-4 bg-gray-50 border-l-4 border-indigo-500 rounded-md">
          <p className="text-sm text-gray-600">The encryption nonce is stored in the first 32 bytes of the file. Simply select this file for decryption when needed.</p>
        </div>
      )}
    </div>
  );
}
