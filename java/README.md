# Java extension architecture

Python remains the CyberInvestigator orchestrator. Java modules provide an
optional high-performance plugin boundary for parsers, memory-intensive work,
and enterprise integrations.

Every future plugin must extend
`ai.cyberinvestigator.shared.AbstractJavaInvestigationPlugin`. The SDK enforces
the common JSON request/response envelope, structured error responses, and
injectable logging; plugin implementations provide only metadata and their
`process(PluginRequest)` method.

Every distributable Java plugin places a `cyberinvestigator-java-plugin.json`
file beside its JAR. Python discovers these manifests recursively from the
configured `JAVA_PLUGINS_FOLDER`; no plugin path is embedded in Python code.

```json
{
  "name": "example-parser",
  "version": "1.0.0",
  "author": "Example Team",
  "description": "Example Java plugin",
  "supported_artifact_types": ["pdf"],
  "supported_investigation_stages": ["triage"],
  "required_java_version": "21",
  "transport": "jar",
  "jar_file": "example-parser.jar"
}
```

For the optional remote deployment mode, use `"transport": "rest"` and a
`"rest_endpoint"` string. The Python REST transport is intentionally a
dependency-injected interface until an enterprise HTTP client is selected.

The PDF Analyzer is the first SDK-compliant plugin. Build its self-contained
JAR and adjacent descriptor with `gradle :plugins:pdf:assemblePlugin`, then
deploy the contents of `plugins/pdf/build/plugin-distribution/` beneath the
configured `JAVA_PLUGINS_FOLDER`.
