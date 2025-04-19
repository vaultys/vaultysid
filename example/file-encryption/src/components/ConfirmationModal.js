import React from "react";

export default function ConfirmationModal({ isOpen, title, message, onConfirm, onCancel }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center overflow-x-hidden overflow-y-auto outline-none focus:outline-none bg-gray-800 bg-opacity-75">
      <div className="relative w-full max-w-md p-5 mx-auto my-6 bg-white rounded-lg shadow-xl">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <h3 className="text-xl font-semibold text-gray-900">{title}</h3>
          <button className="text-gray-400 hover:text-gray-800 focus:outline-none" onClick={onCancel}>
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="relative flex-auto mb-6">
          <p className="text-gray-600">{message}</p>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-200">
          <button className="px-4 py-2 text-gray-700 bg-gray-200 rounded-md hover:bg-gray-300 focus:outline-none" onClick={onCancel}>
            Cancel
          </button>
          <button className="px-4 py-2 text-white bg-red-600 rounded-md hover:bg-red-700 focus:outline-none" onClick={onConfirm}>
            Reset Identity
          </button>
        </div>
      </div>
    </div>
  );
}
