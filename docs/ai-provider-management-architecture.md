# AI Provider and Model Management

CyberInvestigator retains a provider-neutral application boundary. Investigation
features submit `AIRequest` contracts; provider adapters own SDK, HTTP,
authentication, and response translation details.

## Provider adapters

Ollama and OpenAI have executable adapters. Gemini and Perplexity remain
registered, explicitly unavailable adapters until their runtimes are
implemented. Their configured state never implies availability. The registry
can add further cloud or local adapters without changing investigation APIs.

Provider health includes a source:

- `live_endpoint` means an endpoint was contacted.
- `configuration` means adapter readiness is based only on configuration.
- `adapter` means the adapter declares its implementation state.

Connection tests are explicit privileged operations. Failures suppress provider
error details that could contain sensitive configuration.
Local provider endpoints must use a host in `AI_ALLOWED_PROVIDER_HOSTS`.
Embedded URL credentials are rejected, reducing server-side request-forgery
exposure while allowing explicitly approved enterprise inference hosts.

## Credential vault

Provider credentials are encrypted with Fernet before persistence. The
encryption key is derived from `AI_CREDENTIAL_ENCRYPTION_KEY`, or from the
production-required `SECRET_KEY` when a dedicated key is not configured.
Encrypted values use the `secret.ai` namespace, which is excluded from the
general settings API.

Plaintext credentials are accepted only by the privileged provider update
operation, used to rebuild the runtime adapter, and never returned, logged, or
included in audit reasons. Changing the encryption key requires an explicit
credential rotation procedure.

## Models and workloads

Workloads have independent provider and model assignments:

- general, cybersecurity, and investigation chat;
- evidence analysis;
- timeline summaries;
- report analysis;
- threat-intelligence summaries.

Chat invocation currently consumes these assignments directly. Other workloads
have stable assignments ready for their provider invocation paths. When
failover selects a different adapter, that adapter's configured model is used
instead of sending a provider-incompatible model identifier.

## Prompt versions

Managed prompt versions are immutable settings records. Creating a replacement
requires a new version identifier. An active pointer selects a version per
workload. Managed chat instructions are appended to the immutable
CyberInvestigator safety and evidence-grounding prompt; administrators cannot
replace the platform safety baseline through the management API.

## Failover

The registry supports an audited, allow-listed provider order and an enable
flag. When disabled, an unavailable selected provider fails closed to the
existing deterministic local investigation behavior. No hidden provider switch
occurs.

## Usage and observability

Usage aggregates only persisted `AIReasoning` records and provider-reported
token counts. Missing token counts are displayed as unavailable. The platform
does not estimate latency, cost, availability, or consumption.

Every provider, workload, prompt, failover, settings, and connection-test action
is protected by `settings.manage` and recorded through the shared audit path.
