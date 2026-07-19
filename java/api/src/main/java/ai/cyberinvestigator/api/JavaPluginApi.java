package ai.cyberinvestigator.api;

import ai.cyberinvestigator.shared.PluginRequest;
import ai.cyberinvestigator.shared.PluginResponse;

/**
 * Future REST service boundary for remotely hosted Java plugins.
 *
 * <p>A framework adapter may expose this interface over HTTP while preserving
 * the same JSON contract used by the local JAR transport.</p>
 */
public interface JavaPluginApi {
    /**
     * Accepts a normalized plugin request and returns a normalized response.
     *
     * @param request JSON-compatible plugin request
     * @return JSON-compatible plugin response
     */
    PluginResponse execute(PluginRequest request);
}
