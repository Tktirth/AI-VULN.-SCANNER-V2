"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/utils/api";
import SeverityDonut from "@/components/SeverityDonut";
import FindingsTable, { Finding } from "@/components/FindingsTable";

export default function DashboardPage() {
  const router = useRouter();
  const [profile, setProfile] = useState<any>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [jobsCount, setJobsCount] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("firebase_token");
    if (!token) {
      router.push("/login");
      return;
    }

    const fetchData = async () => {
      try {
        const userProfile = await api.get("auth/profile");
        setProfile(userProfile);

        const findingsList = await api.get("findings");
        setFindings(findingsList);

        const jobsList = await api.get("scan-jobs");
        setJobsCount(jobsList.length);
      } catch (err: any) {
        setError(err.message || "Failed to load dashboard data");
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [router]);

  const handleLogout = () => {
    localStorage.removeItem("firebase_token");
    router.push("/login");
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-gray-400">
        <div className="flex flex-col items-center space-y-4">
          <span className="w-8 h-8 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin"></span>
          <p className="text-sm">Loading security dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="glass-card max-w-md w-full p-6 rounded-2xl text-center space-y-4">
          <h2 className="text-xl font-bold text-red-400">Dashboard Error</h2>
          <p className="text-gray-300 text-sm">{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm transition"
          >
            Retry Loading
          </button>
        </div>
      </div>
    );
  }

  // Calculate severity counts for Donut
  const counts = {
    critical: findings.filter((f) => f.severity.toLowerCase() === "critical").length,
    high: findings.filter((f) => f.severity.toLowerCase() === "high").length,
    medium: findings.filter((f) => f.severity.toLowerCase() === "medium").length,
    low: findings.filter((f) => f.severity.toLowerCase() === "low").length,
  };

  const slaBreachedCount = findings.filter(
    (f) => new Date(f.sla_deadline).getTime() < new Date().getTime()
  ).length;

  const slaComplianceRate =
    findings.length > 0
      ? Math.round(((findings.length - slaBreachedCount) / findings.length) * 100)
      : 100;

  return (
    <div className="min-h-screen flex flex-col">
      {/* Navbar */}
      <header className="glass-card border-x-0 border-t-0 rounded-none relative z-20">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <span className="w-6 h-6 rounded bg-gradient-to-r from-violet-500 to-indigo-500 flex-shrink-0 animate-pulse" />
            <span className="font-extrabold text-lg text-white">AI-VULN-SCANNER</span>
          </div>

          <div className="flex items-center space-x-4">
            <span className="text-sm text-gray-300 font-medium">
              {profile?.email} ({profile?.role})
            </span>
            <button
              onClick={handleLogout}
              className="px-3.5 py-1.5 rounded-lg border border-gray-800 hover:border-gray-700 hover:bg-gray-800/40 text-gray-300 hover:text-white text-xs font-semibold transition"
            >
              Sign Out
            </button>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8 space-y-8 relative z-10">
        {/* Hero title */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-extrabold text-white tracking-tight">Security Dashboard</h1>
            <p className="text-gray-400 text-sm mt-1">
              Real-time vulnerability findings and platform status
            </p>
          </div>
          <button
            onClick={() => router.push("/scan")}
            className="md:self-center px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-sm font-semibold transition shadow-lg shadow-indigo-600/20"
          >
            Start New Scan
          </button>
        </div>

        {/* Metric cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="glass-card p-6 rounded-2xl">
            <p className="text-xs uppercase tracking-wider font-bold text-gray-500">Total Scans</p>
            <p className="text-3xl font-extrabold text-white mt-2">{jobsCount}</p>
          </div>
          <div className="glass-card p-6 rounded-2xl">
            <p className="text-xs uppercase tracking-wider font-bold text-gray-500">
              Active Findings
            </p>
            <p className="text-3xl font-extrabold text-white mt-2">{findings.length}</p>
          </div>
          <div className="glass-card p-6 rounded-2xl">
            <p className="text-xs uppercase tracking-wider font-bold text-gray-500">
              SLA Breaches
            </p>
            <p className={`text-3xl font-extrabold mt-2 ${slaBreachedCount > 0 ? "text-red-400" : "text-emerald-400"}`}>
              {slaBreachedCount}
            </p>
          </div>
          <div className="glass-card p-6 rounded-2xl">
            <p className="text-xs uppercase tracking-wider font-bold text-gray-500">
              SLA Compliance
            </p>
            <p className="text-3xl font-extrabold text-white mt-2">{slaComplianceRate}%</p>
          </div>
        </div>

        {/* Donut and Table section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
          {/* Donut container */}
          <div className="glass-card p-6 rounded-2xl lg:col-span-1 flex flex-col items-center">
            <h3 className="text-sm font-bold text-gray-400 self-start uppercase tracking-wider">
              Findings Breakdown
            </h3>
            <SeverityDonut counts={counts} />
          </div>

          {/* Table container */}
          <div className="glass-card p-6 rounded-2xl lg:col-span-2 space-y-4">
            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">
              Recent Vulnerabilities
            </h3>
            <FindingsTable findings={findings} />
          </div>
        </div>
      </main>
    </div>
  );
}
