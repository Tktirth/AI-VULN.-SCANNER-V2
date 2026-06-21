"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/utils/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@seedcorp.com");
  const [password, setPassword] = useState("password");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // If already logged in, redirect to dashboard
    if (localStorage.getItem("firebase_token")) {
      router.push("/");
    }
  }, [router]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      // For local development / compose mode, we bypass live Firebase
      // and set our mock dev_token
      if (email === "admin@seedcorp.com") {
        localStorage.setItem("firebase_token", "dev_token");
        // Verify token against backend
        await api.get("auth/profile", { token: "dev_token" });
        router.push("/");
      } else {
        setError("Invalid email. For local testing, please use admin@seedcorp.com");
      }
    } catch (err: any) {
      setError(err.message || "Failed to authenticate");
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = async () => {
    setError(null);
    setLoading(true);
    try {
      localStorage.setItem("firebase_token", "dev_token");
      await api.get("auth/profile", { token: "dev_token" });
      router.push("/");
    } catch (err: any) {
      setError(err.message || "Failed to authenticate");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 relative">
      <div className="glass-card w-full max-w-md p-8 rounded-2xl flex flex-col space-y-6">
        <div className="text-center">
          <h1 className="text-3xl font-extrabold tracking-tight bg-gradient-to-r from-violet-400 to-indigo-400 bg-clip-text text-transparent">
            AI Vulnerability Scanner
          </h1>
          <p className="text-gray-400 mt-2 text-sm">
            Sign in to start scanning and securing your web assets
          </p>
        </div>

        {error && (
          <div className="bg-red-950/50 border border-red-800/80 text-red-200 px-4 py-3 rounded-lg text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Email Address
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-white placeholder-gray-500 text-sm outline-none transition"
              placeholder="name@company.com"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Password
            </label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-white placeholder-gray-500 text-sm outline-none transition"
              placeholder="••••••••"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium text-sm transition shadow-lg shadow-indigo-600/20"
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <div className="relative flex py-2 items-center">
          <div className="flex-grow border-t border-gray-800"></div>
          <span className="flex-shrink mx-4 text-gray-500 text-xs uppercase">Or</span>
          <div className="flex-grow border-t border-gray-800"></div>
        </div>

        <button
          onClick={handleDemoLogin}
          disabled={loading}
          className="w-full py-2.5 rounded-lg bg-gray-850 hover:bg-gray-800 border border-gray-700 text-gray-200 font-medium text-sm transition"
        >
          Quick Demo Sign In
        </button>
      </div>
    </div>
  );
}
