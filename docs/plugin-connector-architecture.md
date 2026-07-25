# Plugin, Integration, and Connector Architecture

CyberInvestigator extends its existing trusted-directory plugin loader with
provider-neutral connector contracts, least-privilege activation, encrypted
configuration, asynchronous operations, and semantic auditing.

## Trust and execution boundary

Python plugins are imported into the application process and therefore remain
trusted code. Python cannot safely sandbox arbitrary imports. Only packages
approved by an administrator and placed under the configured plugin root are
eligible for loading. Future untrusted plugins must execute through an external
worker or container boundary.

New ZIP uploads are validated before extraction:

- maximum member count and expanded size;
- no path traversal, symbolic links, or encrypted members;
- exactly one root `plugin.toml`;
- a declared 64-character module SHA-256, subsequently verified by the loader.

The signature and publisher interfaces remain extension points. The platform
does not claim a signature, publisher, update, or compatibility result unless a
real evaluator supplies it.

## Plugin contract

`PluginMetadata` remains immutable and backward compatible. Enterprise metadata
adds:

- a category such as analysis, SIEM, EDR, threat intelligence, ticketing,
  storage, messaging, or identity;
- explicitly requested runtime permissions;
- a configuration schema that identifies secret fields.

Plugins without these fields retain analysis-category behavior and request no
permissions.

## Least privilege

The loader checks requested permissions every time a plugin is enabled.
Administrators may grant only permissions declared by the plugin and present in
the platform allow-list. Missing grants fail closed. Existing capability labels
do not implicitly grant file, network, evidence, report, or secret access.

## Connector contract

Integration plugins may implement `EnterpriseConnector`:

- `health()` returns a typed `ConnectorHealth`;
- `synchronize()` returns a typed `ConnectorSyncResult`.

Unsupported operations return unavailable rather than simulated results.
Operations run through the existing background-job dispatcher. Only normalized
health and synchronization fields are persisted; protected provider failures
remain in server logs.

## Configuration and credentials

Public configuration values are accepted only when declared by the plugin
schema. Credential keys must be explicitly marked `secret`. Credentials are
encrypted with Fernet under `PLUGIN_CREDENTIAL_ENCRYPTION_KEY`, falling back to
the production-required `SECRET_KEY`. The general settings API excludes every
`secret.*` namespace.

Plaintext credentials are never returned, rendered, or included in audit
reasons. Decrypted credentials exist only for the duration of a connector
operation inside the current trusted-process boundary.

## Lifecycle and audit

Discovery, installation, validation, enablement, disablement, update, removal,
configuration changes, queued connector operations, and completed or failed
operations create actor-attributed audit records. Removal also deletes the
plugin's persisted configuration, encrypted credential, grants, health, and
synchronization cursor.

## Marketplace preparation

The management API intentionally returns an empty update list and an explicit
notice when no marketplace source is configured. A future marketplace must add
real publisher trust, signature verification, compatibility evaluation, update
metadata, and isolated installation before update availability can be shown.
