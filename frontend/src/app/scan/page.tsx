"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/utils/api";

export default function ScanWizardPage() {
  const router = useRouter();
  const [profile, setProfile] = useState<any>(null);
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Wizard state
  const [step, setStep] = useState(1);
  
  // Form fields
  const [projectId, setProjectId] = useState("");
  const [newProjectName, setNewProjectName] = useState("");
  const [isCreatingProject, setIsCreatingProject] = useState(false);

  const [targetUrl, setTargetUrl] = useState("http://example.com");

  const [authMethod, setAuthMethod] = useState<"none" | "cookie" | "form">("none");
  const [cookieString, setCookieString] = useState("");
  const [formLoginUrl, setFormLoginUrl] = useState("");
  const [formUsernameField, setFormUsernameField] = useState("username");
  const [formPasswordField, setFormPasswordField] = useState("password");
  const [formUsernameValue, setFormUsernameValue] = useState("");
  const [formPasswordValue, setFormPasswordValue] = useState("");
  const [formPostLoginUrl, setFormPostLoginUrl] = useState("");

  const [authorized, setAuthorized] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("firebase_token");
    if (!token) {
      router.push("/login");
      return;
    }

    const loadInitialData = async () => {
      try {
        const userProfile = await api.get("auth/profile");
        setProfile(userProfile);

        const projectList = await api.get("projects");
        setProjects(projectList);
        if (projectList.length > 0) {
          setProjectId(projectList[0].id);
        } else {
          setIsCreatingProject(true);
        }
      } catch (err: any) {
        setError(err.message || "Failed to load projects");
      } finally {
        setLoading(false);
      }
    };

    loadInitialData();
  }, [router]);

  const handleCreateProject = async () => {
    if (!newProjectName.trim()) return;
    setError(null);
    try {
      const newProj = await api.post("projects", {
        name: newProjectName,
        organization_id: profile.organization_id,
      });
      setProjects([...projects, newProj]);
      setProjectId(newProj.id);
      setIsCreatingProject(false);
      setNewProjectName("");
    } catch (err: any) {
      setError(err.message || "Failed to create project");
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authorized) return; // double safeguard
    setError(null);
    setSubmitting(true);

    try {
      const job = await api.post("scan-jobs", {
        project_id: projectId,
        target_url: targetUrl,
        authorization_confirmed: authorized,
      });
      
      // Save auth details locally or pass them to backend if needed
      // Redirect to the Live Scan View page
      router.push(`/scan/${job.id}`);
    } catch (err: any) {
      setError(err.message || "Failed to launch scan job");
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-gray-400">
        <div className="flex flex-col items-center space-y-4">
          <span className="w-8 h-8 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin"></span>
          <p className="text-sm">Loading scan configurations...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen py-12 px-4 sm:px-6 relative z-10">
      <div className="max-w-3xl mx-auto space-y-8">
        {/* Wizard Header */}
        <div className="flex items-center justify-between">
          <div>
            <button
              onClick={() => router.push("/")}
              className="text-xs text-indigo-400 hover:text-indigo-300 font-semibold mb-2 block"
            >
              &larr; Back to Dashboard
            </button>
            <h1 className="text-3xl font-extrabold text-white tracking-tight">Configure New Scan</h1>
            <p className="text-gray-400 text-sm mt-1">Configure target scope, auth, and launch the scanner</p>
          </div>
          <div className="text-right">
            <span className="text-xs font-bold uppercase tracking-wider text-gray-500">Step</span>
            <p className="text-3xl font-extrabold text-white">{step} / 5</p>
          </div>
        </div>

        {error && (
          <div className="bg-red-950/50 border border-red-800/80 text-red-200 px-4 py-3 rounded-lg text-sm">
            {error}
          </div>
        )}

        {/* Form Container */}
        <form onSubmit={handleSubmit} className="glass-card p-8 rounded-2xl space-y-8">
          
          {/* Step 1: Select Project */}
          {step === 1 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-white mb-2">Step 1: Select Project Scope</h3>
                <p className="text-xs text-gray-400">Scan results will be grouped under this project</p>
              </div>

              {!isCreatingProject ? (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Select Project</label>
                    <select
                      value={projectId}
                      onChange={(e) => setProjectId(e.target.value)}
                      className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 text-white text-sm outline-none transition"
                    >
                      {projects.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name}
                        </option>
                      ))}
                    </select>
                  </div>
                  <button
                    type="button"
                    onClick={() => setIsCreatingProject(true)}
                    className="text-xs text-indigo-400 hover:text-indigo-300 font-semibold"
                  >
                    + Create New Project
                  </button>
                </div>
              ) : (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">New Project Name</label>
                    <input
                      type="text"
                      value={newProjectName}
                      onChange={(e) => setNewProjectName(e.target.value)}
                      className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 text-white placeholder-gray-500 text-sm outline-none transition"
                      placeholder="e.g. Production Web App"
                    />
                  </div>
                  <div className="flex space-x-3">
                    <button
                      type="button"
                      onClick={handleCreateProject}
                      className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition"
                    >
                      Save Project
                    </button>
                    {projects.length > 0 && (
                      <button
                        type="button"
                        onClick={() => setIsCreatingProject(false)}
                        className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs font-semibold transition"
                      >
                        Cancel
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 2: Target URL */}
          {step === 2 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-white mb-2">Step 2: Target Endpoint</h3>
                <p className="text-xs text-gray-400">The root URL address to crawl and inspect for vulnerabilities</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Target URL</label>
                <input
                  type="url"
                  required
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 text-white text-sm outline-none transition"
                  placeholder="https://example.com"
                />
              </div>
            </div>
          )}

          {/* Step 3: Auth Configuration */}
          {step === 3 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-white mb-2">Step 3: Authenticated Crawling</h3>
                <p className="text-xs text-gray-400">Configure authentication credentials to scan pages behind login portals</p>
              </div>

              {/* Radio options */}
              <div className="grid grid-cols-3 gap-4">
                {["none", "cookie", "form"].map((method) => (
                  <label
                    key={method}
                    className={`flex flex-col items-center justify-center p-4 rounded-xl border cursor-pointer transition capitalize ${
                      authMethod === method
                        ? "border-indigo-500 bg-indigo-500/5 text-white"
                        : "border-gray-800 bg-gray-900/40 text-gray-400 hover:border-gray-700"
                    }`}
                  >
                    <input
                      type="radio"
                      name="auth_method"
                      value={method}
                      checked={authMethod === method}
                      onChange={() => setAuthMethod(method as any)}
                      className="sr-only"
                    />
                    <span className="text-sm font-bold">{method}</span>
                  </label>
                ))}
              </div>

              {/* Conditional auth fields */}
              {authMethod === "cookie" && (
                <div className="space-y-4 animate-fadeIn">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Cookie Headers</label>
                    <textarea
                      value={cookieString}
                      onChange={(e) => setCookieString(e.target.value)}
                      rows={3}
                      className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 text-white text-sm outline-none transition font-mono"
                      placeholder="session_id=abcdef123456; user_role=admin"
                    />
                  </div>
                </div>
              )}

              {authMethod === "form" && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-fadeIn">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Login URL</label>
                    <input
                      type="url"
                      value={formLoginUrl}
                      onChange={(e) => setFormLoginUrl(e.target.value)}
                      className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 text-white text-sm outline-none transition"
                      placeholder="https://example.com/login"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Post-Login Verification URL</label>
                    <input
                      type="url"
                      value={formPostLoginUrl}
                      onChange={(e) => setFormPostLoginUrl(e.target.value)}
                      className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 text-white text-sm outline-none transition"
                      placeholder="https://example.com/dashboard"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Username Field Name</label>
                    <input
                      type="text"
                      value={formUsernameField}
                      onChange={(e) => setFormUsernameField(e.target.value)}
                      className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 text-white text-sm outline-none transition"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Password Field Name</label>
                    <input
                      type="text"
                      value={formPasswordField}
                      onChange={(e) => setFormPasswordField(e.target.value)}
                      className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 text-white text-sm outline-none transition"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Username Value</label>
                    <input
                      type="text"
                      value={formUsernameValue}
                      onChange={(e) => setFormUsernameValue(e.target.value)}
                      className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 text-white text-sm outline-none transition"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Password Value</label>
                    <input
                      type="password"
                      value={formPasswordValue}
                      onChange={(e) => setFormPasswordValue(e.target.value)}
                      className="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-800 focus:border-indigo-500 text-white text-sm outline-none transition"
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 4: Scan Details */}
          {step === 4 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-white mb-2">Step 4: Review Configuration</h3>
                <p className="text-xs text-gray-400">Confirm target details before proceeding to authorization</p>
              </div>

              <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-6 space-y-4 text-sm">
                <div className="grid grid-cols-3 gap-2">
                  <span className="text-gray-400">Project:</span>
                  <span className="col-span-2 text-white font-semibold">
                    {projects.find((p) => p.id === projectId)?.name || "N/A"}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <span className="text-gray-400">Target URL:</span>
                  <span className="col-span-2 text-white font-mono break-all">{targetUrl}</span>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <span className="text-gray-400">Authentication:</span>
                  <span className="col-span-2 text-white font-semibold capitalize">{authMethod}</span>
                </div>
              </div>
            </div>
          )}

          {/* Step 5: Authorization & Submit */}
          {step === 5 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-bold text-white mb-2">Step 5: Authorization & Launch</h3>
                <p className="text-xs text-gray-400">Confirm you are authorized to run security scans on this target</p>
              </div>

              <div className="bg-yellow-950/20 border border-yellow-900/80 text-yellow-200/90 rounded-xl p-5 text-sm leading-relaxed space-y-2">
                <h4 className="font-bold text-yellow-400">Legal Agreement & Scope authorization</h4>
                <p>
                  Security scanning involves probing for potential vulnerabilities which may generate
                  significant request logs or transient loads on the target server.
                </p>
                <p>
                  By proceeding, you declare that you have explicit permission from the system owner
                  to perform passive and active security assessments on this target.
                </p>
              </div>

              <label className="flex items-start space-x-3 cursor-pointer p-4 border border-gray-800 bg-gray-900/20 rounded-xl hover:border-gray-700 transition">
                <input
                  type="checkbox"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  className="w-4 h-4 rounded text-indigo-600 bg-gray-900 border-gray-800 focus:ring-indigo-500 focus:ring-offset-gray-900 mt-0.5"
                />
                <span className="text-xs text-gray-300 leading-tight">
                  I explicitly authorize the AI Vulnerability Scanner to execute security scanning
                  probes, crawlers, and attack simulators on the configured target URL.
                </span>
              </label>
            </div>
          )}

          {/* Navigation Controls */}
          <div className="flex justify-between border-t border-gray-850 pt-6">
            <button
              type="button"
              disabled={step === 1 || submitting}
              onClick={() => setStep(step - 1)}
              className="px-4 py-2 bg-gray-850 hover:bg-gray-800 disabled:opacity-30 text-gray-300 rounded-lg text-sm font-semibold transition"
            >
              Previous
            </button>

            {step < 5 ? (
              <button
                type="button"
                onClick={() => setStep(step + 1)}
                className="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-semibold transition"
              >
                Next
              </button>
            ) : (
              <button
                type="submit"
                disabled={!authorized || submitting}
                className="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:hover:bg-indigo-600 text-white rounded-lg text-sm font-bold transition shadow-lg shadow-indigo-600/10"
              >
                {submitting ? "Launching Scan..." : "Confirm & Launch"}
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  );
}
