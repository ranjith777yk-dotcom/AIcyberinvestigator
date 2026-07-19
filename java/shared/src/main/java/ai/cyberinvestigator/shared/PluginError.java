package ai.cyberinvestigator.shared;

import java.util.Objects;

/** JSON-safe structured error returned by a Java plugin. */
public record PluginError(PluginErrorCode code, String message) {
    /** Validates a public error without allowing null or blank diagnostics. */
    public PluginError {
        code = Objects.requireNonNull(code, "code must not be null");
        if (message == null || message.isBlank()) {
            throw new IllegalArgumentException("message must not be blank");
        }
        message = message.trim();
    }
}
