package ai.cyberinvestigator.plugins.pdf;

import ai.cyberinvestigator.shared.PluginError;
import ai.cyberinvestigator.shared.PluginErrorCode;
import ai.cyberinvestigator.shared.PluginRequest;
import ai.cyberinvestigator.shared.PluginResponse;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * JSON-over-standard-stream JAR entry point for the PDF Analyzer plugin.
 *
 * <p>It accepts one SDK request JSON object from standard input and writes
 * exactly one SDK response JSON object to standard output.</p>
 */
public final class PdfAnalyzerPluginMain {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private PdfAnalyzerPluginMain() {
    }

    /** Executes the plugin launcher without emitting non-JSON output to standard output. */
    public static void main(String[] arguments) throws IOException {
        JsonNode root = OBJECT_MAPPER.readTree(System.in);
        PluginResponse response;
        if (root == null || !root.isObject()) {
            response = PluginResponse.failure(
                    UUID.randomUUID().toString(),
                    new PluginError(PluginErrorCode.INVALID_REQUEST, "Plugin input must be a JSON object."));
        } else {
            try {
                response = new PdfAnalyzerPlugin().execute(toRequest(root));
            } catch (RuntimeException error) {
                response = PluginResponse.failure(
                        root.path("request_id").asText(UUID.randomUUID().toString()),
                        new PluginError(PluginErrorCode.INVALID_REQUEST, "Plugin request is invalid."));
            }
        }
        OBJECT_MAPPER.writeValue(System.out, response);
    }

    /** Converts a JSON object into the immutable SDK request model. */
    private static PluginRequest toRequest(JsonNode root) {
        String requestId = root.path("request_id").asText(UUID.randomUUID().toString());
        Instant requestedAt = parseInstant(root.path("requested_at").asText(null));
        Map<String, Object> payload = root.has("payload") && root.get("payload").isObject()
                ? OBJECT_MAPPER.convertValue(root.get("payload"), new TypeReference<>() {
                })
                : Map.of();
        return new PluginRequest(requestId, requestedAt, payload);
    }

    /** Parses an optional RFC 3339 timestamp and falls back to the current instant. */
    private static Instant parseInstant(String value) {
        try {
            return value == null || value.isBlank() ? Instant.now() : Instant.parse(value);
        } catch (RuntimeException ignored) {
            return Instant.now();
        }
    }
}
