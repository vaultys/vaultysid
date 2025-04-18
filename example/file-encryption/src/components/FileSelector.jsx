import { useRef } from "react";

export default function FileSelector({ file, onFileChange }) {
  const fileInputRef = useRef(null);

  return (
    <div className="mb-6">
      <input type="file" onChange={onFileChange} ref={fileInputRef} className="hidden" />
      <button onClick={() => fileInputRef.current.click()} className="w-full py-3 border border-dashed border-gray-400 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors text-gray-700 mb-3">
        Select File
      </button>
      {file && <div className="text-sm text-gray-600 mt-2">Selected: {file.name}</div>}
    </div>
  );
}
