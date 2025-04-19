export default function Layout({ children, title = "VaultysID File Encryption" }) {
  return (
    <div className="max-w-3xl mx-auto px-4 py-8 md:px-6">
      <h1 className="text-3xl font-bold text-center text-indigo-800 mb-8">{title}</h1>
      {children}
    </div>
  );
}
