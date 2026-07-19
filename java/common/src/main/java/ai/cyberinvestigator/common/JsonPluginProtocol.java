package ai.cyberinvestigator.common;

/**
 * Names the JSON-over-standard-stream protocol used by local Java plugin JARs.
 *
 * <p>Concrete serialization is intentionally delegated to the selected plugin
 * runtime adapter. Request and response envelopes are defined in the shared
 * Java Plugin SDK and remain framework-independent.</p>
 */
public interface JsonPluginProtocol {
    /** Standard input content type for plugin requests. */
    String REQUEST_CONTENT_TYPE = "application/json";

    /** Standard output content type for plugin responses. */
    String RESPONSE_CONTENT_TYPE = "application/json";
}
