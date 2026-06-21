"use client";

import { useState } from "react";
import SLAIndicator from "./SLAIndicator";

export interface Finding {
  id: string;
  title: string;
  severity: string;
  sla_deadline: string;
  scan_job_id: string;
  url?: string;
  parameter?: string;
  evidence?: string;
  description?: string;
  remediation?: string;
}

interface FindingsTableProps {
  findings: Finding[];
}

export default function FindingsTable({ findings }: FindingsTableProps) {
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);

  const getSeverityStyles = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-950/40 border border-red-800 text-red-400";
      case "high":
        return "bg-orange-950/40 border border-orange-800 text-orange-400";
      case "medium":
        return "bg-yellow-950/40 border border-yellow-800 text-yellow-400";
      case "low":
        return "bg-green-950/40 border border-green-800 text-green-400";
      default:
        return "bg-gray-800 border border-gray-700 text-gray-300";
    }
  };

  const handleRowClick = (id: string) => {
    setSelectedFinding(selectedFinding === id ? null : id);
  };

  const handleKeyDown = (e: React.KeyboardEvent, id: string) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleRowClick(id);
    }
  };

  return (
    <div className="w-full space-y-4">
      <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900/40">
        <table className="w-full text-left border-collapse text-sm">
          <thead>
            <tr className="border-b border-gray-800 bg-gray-900/80 text-gray-400 font-medium">
              <th className="px-6 py-4">Finding</th>
              <th className="px-6 py-4">Severity</th>
              <th className="px-6 py-4">SLA Status</th>
              <th className="px-6 py-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60">
            {findings.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-6 py-8 text-center text-gray-500">
                  No findings recorded. Excellent security health!
                </td>
              </tr>
            ) : (
              findings.map((finding) => {
                const isOpen = selectedFinding === finding.id;
                return (
                  <caption
                    key={finding.id}
                    className="contents"
                  >
                    <tr
                      tabIndex={0}
                      onClick={() => handleRowClick(finding.id)}
                      onKeyDown={(e) => handleKeyDown(e, finding.id)}
                      className={`cursor-pointer hover:bg-gray-800/40 outline-none transition-colors ${
                        isOpen ? "bg-gray-800/20" : ""
                      }`}
                    >
                      <td className="px-6 py-4 font-semibold text-white">
                        {finding.title}
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold ${getSeverityStyles(
                            finding.severity
                          )}`}
                        >
                          {finding.severity}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <SLAIndicator
                          deadline={finding.sla_deadline}
                          severity={finding.severity}
                        />
                      </td>
                      <td className="px-6 py-4 text-right text-gray-400">
                        <button className="text-indigo-400 hover:text-indigo-300 font-semibold focus:outline-none">
                          {isOpen ? "Hide Details" : "View Details"}
                        </button>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan={4} className="px-6 py-5 bg-gray-900/60 text-gray-300">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="space-y-3">
                              <div>
                                <h4 className="text-xs uppercase tracking-wider text-gray-500 font-bold">
                                  Description
                                </h4>
                                <p className="mt-1 text-sm text-gray-200">
                                  {finding.description || "No description provided."}
                                </p>
                              </div>
                              {finding.evidence && (
                                <div>
                                  <h4 className="text-xs uppercase tracking-wider text-gray-500 font-bold">
                                    Evidence
                                  </h4>
                                  <pre className="mt-1.5 p-3 rounded-lg bg-black/60 text-xs font-mono text-emerald-400 overflow-x-auto border border-gray-800/80">
                                    {finding.evidence}
                                  </pre>
                                </div>
                              )}
                            </div>
                            <div className="space-y-3">
                              {finding.remediation && (
                                <div>
                                  <h4 className="text-xs uppercase tracking-wider text-gray-500 font-bold">
                                    Remediation & Action Plan
                                  </h4>
                                  <p className="mt-1 text-sm text-gray-200">
                                    {finding.remediation}
                                  </p>
                                </div>
                              )}
                              {finding.url && (
                                <div>
                                  <h4 className="text-xs uppercase tracking-wider text-gray-500 font-bold">
                                    Target Vulnerable Endpoint
                                  </h4>
                                  <span className="mt-1 text-xs font-mono bg-gray-850 px-2 py-1 rounded border border-gray-700 text-indigo-300 break-all inline-block">
                                    {finding.url}
                                  </span>
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </caption>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
