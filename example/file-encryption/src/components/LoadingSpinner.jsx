export default function LoadingSpinner({ message = "Loading..." }) {
  return (
    <div className="flex flex-col items-center justify-center h-48">
      <div className="w-9 h-9 border-4 border-gray-200 rounded-full border-t-indigo-600 animate-spin"></div>
      <p className="mt-4 text-gray-600">{message}</p>
    </div>
  );
}
