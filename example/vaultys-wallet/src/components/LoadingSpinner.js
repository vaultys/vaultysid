export default function LoadingSpinner({ message = "Loading..." }) {
  return (
    <div className="flex flex-col items-center justify-center py-12">
      <div className="w-12 h-12 border-4 border-gray-200 rounded-full border-t-orange-500 animate-spin"></div>
      <p className="mt-4 text-gray-600">{message}</p>
    </div>
  );
}
