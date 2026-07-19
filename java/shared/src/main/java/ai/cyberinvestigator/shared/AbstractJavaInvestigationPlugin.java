package ai.cyberinvestigator.shared;

import java.util.Map;
import java.util.Objects;

/**
 * Mandatory SDK base class for future Java investigation plugins.
 *
 * <p>Subclasses supply metadata and implement {@link #process(PluginRequest)}.
 * This base class centralizes request validation, structured error translation,
 * and internal logging while ensuring standard JSON response envelopes.</p>
 */
public abstract class AbstractJavaInvestigationPlugin implements JavaInvestigationPlugin {
    private final PluginLogger logger;

    /** Creates a plugin using the standard Java Util Logging adapter. */
    protected AbstractJavaInvestigationPlugin() {
        this.logger = JavaUtilPluginLogger.forPlugin(getClass());
    }

    /** Creates a plugin with a dependency-injected logger. */
    protected AbstractJavaInvestigationPlugin(PluginLogger logger) {
        this.logger = Objects.requireNonNull(logger, "logger must not be null");
    }

    /**
     * Executes the SDK lifecycle and returns a JSON-safe response.
     *
     * <p>This method is final so all plugins receive uniform error handling.</p>
     */
    @Override
    public final PluginResponse execute(PluginRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        try {
            validate(request);
            logger.info("Processing request " + request.requestId() + " for " + metadata().name());
            return PluginResponse.success(request.requestId(), process(request));
        } catch (PluginException error) {
            logger.warn("Plugin request " + request.requestId() + " failed: " + error.getMessage());
            return PluginResponse.failure(request.requestId(), new PluginError(error.errorCode(), error.getMessage()));
        } catch (RuntimeException error) {
            logger.error("Unexpected plugin failure for request " + request.requestId(), error);
            return PluginResponse.failure(
                    request.requestId(),
                    new PluginError(PluginErrorCode.INTERNAL_ERROR, "The plugin could not complete the request."));
        }
    }

    /** Validates the normalized request before plugin-specific processing. */
    protected void validate(PluginRequest request) throws PluginException {
        // Subclasses may add schema validation without bypassing SDK error handling.
    }

    /**
     * Implements plugin-specific processing and returns only JSON-safe values.
     *
     * @param request validated normalized request
     * @return JSON object payload
     * @throws PluginException for safe, handled processing failures
     */
    protected abstract Map<String, Object> process(PluginRequest request) throws PluginException;
}
