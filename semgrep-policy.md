# Semgrep SAST policy

Marley runs the Semgrep Community ruleset as a blocking CI control.

The Semgrep engine image used by CI is pinned by digest. The Community
ruleset is currently resolved dynamically through `--config auto`, so the
ruleset itself is not presented as bit-for-bit reproducible.

## Internal HTTP transport to Prometheus

Marley intentionally uses HTTP between the Flask application and Prometheus
on the private Docker `monitoring` network.

The Semgrep rule:

`python.lang.security.audit.insecure-transport.requests.request-with-http.request-with-http`

is therefore suppressed only on the exact `requests.get()` calls that query
the internal Prometheus service.

The rule is not globally excluded from the repository. A future HTTP request
matching the same rule elsewhere remains visible to Semgrep.

These local suppressions must be reconsidered if Prometheus is moved outside
the trusted internal Docker network or if the transport architecture changes.

## Removed historical exceptions

Two previous findings no longer require exceptions:

- the Flask development entrypoint binds to `127.0.0.1` instead of
  `0.0.0.0`;
- the favicon is served as a local static file instead of a `data:` URI.

No global `--exclude-rule` is currently required by the CI workflow.
