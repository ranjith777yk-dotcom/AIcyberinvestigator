package ai.cyberinvestigator.shared;

/** Standard contract implemented by every CyberInvestigator Java plugin. */
public interface JavaInvestigationPlugin {
    /**
     * Returns immutable metadata used by Python discovery, validation, and routing.
     *
     * @return plugin metadata
     */
    PluginMetadata metadata();

    /**
     * Processes one normalized JSON request and returns a JSON-safe response.
     *
     * @param request normalized plugin input
     * @return normalized plugin output
     */
    PluginResponse execute(PluginRequest request);
}
