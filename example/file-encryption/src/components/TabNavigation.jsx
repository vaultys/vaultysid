import Link from "next/link";
import { useRouter } from "next/router";

export default function TabNavigation() {
  const router = useRouter();

  return (
    <div className="flex border-b border-gray-300 mb-6">
      <Link href="/encrypt" className={`px-6 py-3 text-base ${router.pathname === "/encrypt" ? "opacity-100 font-semibold border-b-3 border-indigo-600" : "opacity-70"}`}>
        Encrypt File
      </Link>

      <Link href="/decrypt" className={`px-6 py-3 text-base ${router.pathname === "/decrypt" ? "opacity-100 font-semibold border-b-3 border-indigo-600" : "opacity-70"}`}>
        Decrypt File
      </Link>
    </div>
  );
}
