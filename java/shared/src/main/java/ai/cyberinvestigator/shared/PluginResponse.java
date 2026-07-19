package ai.cyberinvestigator.shared;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Immutable JSON response envelope returned by a Java plugin to Python. */
public record PluginResponse(
        String requestId,
        PluginResponseStatus status,
        Instant completedAt,
        Map<String, Object> payload,
        List<PluginError> errors) {

    /** Validates response identity and defensively copies JSON-safe collection values. */
    public PluginResponse {
        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("requestId must not be blank");
        }
        requestId = requestId.trim();
        status = Objects.requireNonNull(status, "status must not be null");
        completedAt = Objects.requireNonNull(completedAt, "completedAt must not be null");
        payload = Map.copyOf(Objects.requireNonNull(payload, "payload must not be null"));
        errors = List.copyOf(Objects.requireNonNull(errors, "errors must not be null"));
    }

    /** Creates a successful response for one plugin request. */
    public static PluginResponse success(String requestId, Map<String, Object> payload) {
        return new PluginResponse(requestId, PluginResponseStatus.SUCCEEDED, Instant.now(), payload, List.of());
    }

    /** Creates a failed response without exposing an implementation stack trace. */
    public static PluginResponse failure(String requestId, PluginError error) {
        return new PluginResponse(requestId, PluginResponseStatus.FAILED, Instant.now(), Map.of(), List.of(error));
    }
}
