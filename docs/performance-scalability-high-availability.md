# Performance, scalability, and high availability

## Current deployment truth

CyberInvestigator remains an evolutionary modular monolith. Gunicorn provides
multiple threaded web workers, PostgreSQL provides the production persistence
boundary, and an in-process executor handles non-request work. This supports
vertical scaling and stateless web-process replication where an external
platform provides routing and shared storage.

The repository does not claim that the following are deployed:

- a load balancer or replica orchestrator;
- a durable distributed job broker;
- a shared distributed cache;
- PostgreSQL replication or automated failover;
- multi-node evidence object storage;
- an infrastructure metrics collector.

The performance API and workspace show those components as unavailable or
external until a real connector is present.

## Runtime controls

Gunicorn concurrency and lifecycle are configured in `gunicorn.conf.py`.
`WEB_WORKERS` and `WEB_THREADS` control request concurrency per container.
`WEB_MAX_REQUESTS` and jitter recycle workers gradually, while graceful timeout
and the container stop period protect in-flight requests during termination.

Database connections use pre-ping and recycling. Production pool size,
overflow, and checkout timeout are configurable. Total potential connections
must be calculated across every Gunicorn worker and every application replica
before scaling. Testing uses an isolated SQLite-compatible pool configuration.

`BACKGROUND_WORKER_THREADS` controls the local executor. Its queue, running
count, available worker count, completions, and failures are observed directly.
Jobs are non-durable and process-local. Do not use web replica scaling as a
substitute for a durable queue when work must survive restarts.

## Protected caching

Dashboard and investigation-context documents use a bounded TTL/LRU
process-memory cache. Keys include the authenticated role and user identity.
Values are copied on entry and retrieval, never written to disk, and invalidated
after state changes. Capacity, hit/miss, and eviction statistics are measured.

The cache is intentionally not shared across replicas. A future distributed
adapter must encrypt transport, authenticate clients, isolate environments,
preserve tenant/user scope, apply short TTLs, and prohibit caching credentials,
raw evidence bytes, or secrets.

## Operations workspace

Administrators can use `/admin/performance` and
`GET /api/v1/admin/performance`. The mobile information order is Platform
Health, Capacity, Queue Status, then Bottlenecks.

The workspace reports:

- bounded current-process request throughput, latency, and server errors;
- logical CPUs and process memory when the operating system supports it;
- instance-volume capacity and current database-pool counters;
- current process cache and executor statistics;
- only bottlenecks supported by observed queue or eviction evidence;
- explicit gaps in replica, load-balancer, durable-queue, shared-cache,
  database-failover, and shared-storage discovery.

Capacity targets are operator-defined through the audited capacity-plan
endpoint. They are not benchmarks or discovered platform limits. Cache
invalidation is also administrator-only and audited.

## Horizontal scaling prerequisites

Before operating multiple replicas:

1. Use one externally managed PostgreSQL service and size its connection limit
   against all worker pools.
2. Move evidence, reports, backups, and quarantine data to a custody-preserving
   shared storage adapter; a container-local or single-host volume is not a
   multi-node HA boundary.
3. Move required asynchronous work to a durable broker with idempotency,
   retry/backoff, dead-letter handling, and persisted job ownership.
4. Use a shared cache only for explicitly approved derived data.
5. Put replicas behind health-aware routing and perform graceful rolling
   termination.
6. Connect infrastructure metrics and distributed tracing before defining
   scaling policies.
7. Exercise backup restore, database failover, worker interruption, and
   evidence-integrity validation in a non-production environment.

No throughput limit, supported-user count, RPO, RTO, replica count, or
historical capacity trend is inferred by this implementation.
