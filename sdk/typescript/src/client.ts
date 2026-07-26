/** Preview CyberInvestigator v1 client. The OpenAPI document is authoritative. */
export class CyberInvestigatorClient {
  constructor(
    private readonly baseUrl: string,
    private readonly csrfToken?: string,
  ) {}

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const mutating = !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
    const response = await fetch(new URL(path, this.baseUrl), {
      method,
      credentials: "include",
      headers: {
        Accept: "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(mutating && this.csrfToken ? { "X-CSRF-Token": this.csrfToken } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const document = await response.json();
    if (!response.ok) throw new Error(String(document.error ?? `API request failed (${response.status})`));
    if (response.headers.get("API-Version") !== "v1") throw new Error("Unexpected API version.");
    return document as T;
  }

  readiness(): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/v1/health/ready");
  }

  openapi(): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/v1/openapi.json");
  }
}
