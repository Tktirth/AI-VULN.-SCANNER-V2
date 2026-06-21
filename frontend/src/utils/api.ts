const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface RequestOptions extends RequestInit {
  token?: string;
  apiKey?: string;
}

// Simple sleep helper
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function apiRequest<T = any>(
  path: string,
  options: RequestOptions = {}
): Promise<T> {
  const { token, apiKey, ...init } = options;
  const headers = new Headers(init.headers || {});

  // Add Auth headers
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  } else if (typeof window !== "undefined") {
    // Attempt to load Firebase JWT token from localStorage or session
    const savedToken = localStorage.getItem("firebase_token");
    if (savedToken) {
      headers.set("Authorization", `Bearer ${savedToken}`);
    }
  }

  if (apiKey) {
    headers.set("X-API-Key", apiKey);
  }

  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const url = `${API_URL.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;

  let attempts = 0;
  const maxAttempts = 3;

  while (attempts < maxAttempts) {
    attempts++;
    const response = await fetch(url, {
      ...init,
      headers,
    });

    if (response.status === 401) {
      if (typeof window !== "undefined" && !window.location.pathname.includes("/login")) {
        localStorage.removeItem("firebase_token");
        window.location.href = "/login";
      }
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || "Unauthorized");
    }

    if (response.status === 429) {
      const retryAfterHeader = response.headers.get("Retry-After");
      const retryAfterSeconds = retryAfterHeader ? parseInt(retryAfterHeader, 10) : 2;
      console.warn(`Rate limited (429). Retrying after ${retryAfterSeconds}s...`);
      await sleep(retryAfterSeconds * 1000);
      continue;
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `Request failed with status ${response.status}`);
    }

    return response.json();
  }

  throw new Error("Request failed: Max retry attempts exceeded for rate limit.");
}

export const api = {
  get: <T = any>(path: string, options?: RequestOptions) =>
    apiRequest<T>(path, { ...options, method: "GET" }),
  post: <T = any>(path: string, body?: any, options?: RequestOptions) =>
    apiRequest<T>(path, {
      ...options,
      method: "POST",
      body: body ? JSON.stringify(body) : undefined,
    }),
  put: <T = any>(path: string, body?: any, options?: RequestOptions) =>
    apiRequest<T>(path, {
      ...options,
      method: "PUT",
      body: body ? JSON.stringify(body) : undefined,
    }),
  delete: <T = any>(path: string, options?: RequestOptions) =>
    apiRequest<T>(path, { ...options, method: "DELETE" }),
};
