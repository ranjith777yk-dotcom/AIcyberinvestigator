package ai.cyberinvestigator.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/** Preview Java 21 client. The authenticated OpenAPI v1 document is authoritative. */
public final class CyberInvestigatorClient {
    private final URI baseUri;
    private final HttpClient http;

    public CyberInvestigatorClient(URI baseUri) {
        this.baseUri = baseUri;
        this.http = HttpClient.newHttpClient();
    }

    public String get(String path) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve(path))
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("CyberInvestigator API request failed with status " + response.statusCode());
        }
        if (!"v1".equals(response.headers().firstValue("API-Version").orElse(""))) {
            throw new IOException("Unexpected CyberInvestigator API version");
        }
        return response.body();
    }

    public String readiness() throws IOException, InterruptedException {
        return get("/api/v1/health/ready");
    }

    public String openapi() throws IOException, InterruptedException {
        return get("/api/v1/openapi.json");
    }
}
