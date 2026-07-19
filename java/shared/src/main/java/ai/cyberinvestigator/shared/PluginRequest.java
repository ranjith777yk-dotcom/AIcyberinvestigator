package ai.cyberinvestigator.shared;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/** Immutable JSON request envelope passed from Python to a Java plugin. */
public record PluginRequest(
        String requestId,
        Instant requestedAt,
        Map<String, Object> payload) {

    /** Validates the request identifier and defensively copies its JSON object payload. */
    public PluginRequest {
        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("requestId must not be blank");
        }
        requestId = requestId.trim();
        requestedAt = Objects.requireNonNull(requestedAt, "requestedAt must not be null");
        payload = Map.copyOf(Objects.requireNonNull(payload, "payload must not be null"));
    }
}
