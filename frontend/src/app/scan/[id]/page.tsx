"use client";

import { useEffect, useState, useRef } from "react";
import { useParams, useRouter } from "next/navigation";
import { api } from "@/utils/api";
import FindingsTable, { Finding } from "@/components/FindingsTable";

export default function LiveScanViewPage() {
  const { id } = useParams() as { id: string };
  const router = useRouter();
  const [status, setStatus] = useState<string>("pending");
  const [phase, setPhase] = useState<string>("initializing");
  const [percent, setPercent] = useState<number>(0);
  const [message, setMessage] = useState<string>("Setting up environment...");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reportUrl, setReportUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const socketRef = useRef<WebSocket | null>(null);

  // Helper to construct WS URL
  const getWsUrl = (jobId: string) => {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    const wsProtocol = apiUrl.startsWith("https") ? "wss" : "ws";
    const rawHost = apiUrl.replace(/^https?:\/\//, "");
    return `${wsProtocol}://${rawHost.replace(/\/$/, "")}/ws/scan/${jobId}`;
  };

  const fetchFindings = async () => {
    try {
      const allFindings = await api.get("findings");
      const filtered = allFindings.filter((f: Finding) => f.scan_job_id === id);
      setFindings(filtered);
    } catch (err) {
      console.error("Failed to fetch findings:", err);
    }
  };

  const fetchReportUrl = async () => {
    try {
      const res = await api.get(`scan-jobs/${id}/report`);
      if (res.report_url) {
        setReportUrl(res.report_url);
      }
    } catch (err) {
      console.error("Failed to fetch report URL:", err);
    }
  };

  useEffect(() => {
    const token = localStorage.getItem("firebase_token");
    if (!token) {
      router.push("/login");
      return;
    }

    // 1. Initial REST fetch for current job status & findings
    const fetchInitialStatus = async () => {
      try {
        const jobs = await api.get("scan-jobs");
        const currentJob = jobs.find((j: any) => j.id === id);
        if (currentJob) {
          setStatus(currentJob.status);
          if (currentJob.status === "completed" || currentJob.status === "failed") {
            setPercent(100);
            setPhase(currentJob.status);
            setMessage(`Scan job ${currentJob.status}`);
            fetchReportUrl();
          }
        }
        await fetchFindings();
      } catch (err: any) {
        setError(err.message || "Failed to load scan job status");
      }
    };

    fetchInitialStatus();

    // 2. Establish live WebSocket updates
    const wsUrl = getWsUrl(id);
    const ws = new WebSocket(wsUrl);
    socketRef.current = ws;

    ws.onopen = () => {
      console.log(`Connected to WS scan stream for job ${id}`);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.status) setStatus(data.status);
        if (data.phase) setPhase(data.phase);
        if (typeof data.percent === "number") setPercent(data.percent);
        if (data.message) setMessage(data.message);

        // Fetch findings dynamically when progress milestones occur
        fetchFindings();

        if (data.type === "complete" || data.status === "completed") {
          fetchReportUrl();
          ws.close();
        }
      } catch (err) {
        console.error("Failed to parse WebSocket message:", err);
      }
    };

    ws.onerror = (err) => {
      console.error("WebSocket error:", err);
    };

    ws.onclose = () => {
      console.log(`WebSocket closed for job ${id}`);
    };

    // Cleanup logic to prevent zombie connections
    return () => {
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close();
      }
      socketRef.current = null;
    };
  }, [id, router]);

  const getStatusColor = () => {
    switch (status) {
      case "pending":
        return "text-yellow-400";
      case "running":
        return "text-indigo-400 animate-pulse";
      case "completed":
        return "text-emerald-400";
      case "failed":
        return "text-red-400";
      default:
        return "text-gray-400";
    }
  };

  return (
    <div className="min-h-screen py-12 px-4 sm:px-6 relative z-10">
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <button
              onClick={() => router.push("/")}
              className="text-xs text-indigo-400 hover:text-indigo-300 font-semibold mb-2 block"
            >
              &larr; Back to Dashboard
            </button>
            <h1 className="text-3xl font-extrabold text-white tracking-tight">Scan Audit Progress</h1>
            <p className="text-gray-400 text-sm mt-1">Live updates from background auditing pipeline</p>
          </div>
          <div className="text-right">
            <span className="text-xs font-bold uppercase tracking-wider text-gray-500">Status</span>
            <p className={`text-xl font-black capitalize ${getStatusColor()}`}>{status}</p>
          </div>
        </div>

        {error && (
          <div className="bg-red-950/50 border border-red-800/80 text-red-200 px-4 py-3 rounded-lg text-sm">
            {error}
          </div>
        )}

        {/* Live Progress Card */}
        <div className="glass-card p-8 rounded-2xl space-y-6">
          <div className="flex items-center justify-between text-sm">
            <div>
              <span className="text-gray-400 font-medium">Current Phase:</span>{" "}
              <span className="text-white font-bold uppercase tracking-wider bg-gray-800/80 px-2.5 py-1 rounded-md text-xs">
                {phase}
              </span>
            </div>
            <span className="text-indigo-400 font-extrabold text-lg">{percent}%</span>
          </div>

          {/* Progress bar */}
          <div className="w-full h-3 bg-gray-900 border border-gray-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-violet-500 to-indigo-500 rounded-full transition-all duration-500 ease-out"
              style={{ width: `${percent}%` }}
            />
          </div>

          <p className="text-gray-300 text-sm italic font-medium">{message}</p>

          {/* Download report block */}
          {status === "completed" && reportUrl && (
            <div className="pt-4 border-t border-gray-800 animate-fadeIn">
              <a
                href={reportUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-sm font-bold transition shadow-lg shadow-emerald-600/10"
              >
                Download GCS Security Report (.JSON)
              </a>
            </div>
          )}
        </div>

        {/* Live Findings Table */}
        <div className="glass-card p-6 rounded-2xl space-y-4">
          <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">
            Live Vulnerabilities Detected ({findings.length})
          </h3>
          <FindingsTable findings={findings} />
        </div>
      </div>
    </div>
  );
}
