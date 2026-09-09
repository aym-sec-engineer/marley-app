# Semgrep SAST policy

Marley runs the Semgrep Community ruleset as a blocking CI control.

The source files remain in scope for the rest of the ruleset. Three rule IDs
are excluded because the findings were manually reviewed against the deployed
architecture.

## Accepted architectural findings

### HTTP transport to Prometheus

Excluded rule:

`python.lang.security.audit.insecure-transport.requests.request-with-http.request-with-http`

Prometheus is reached through HTTP on the private Docker monitoring network.
This is an internal service-to-service connection, not a public application
endpoint.

### Flask development entrypoint

Excluded rule:

`python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host`

The `app.run()` entrypoint is development-only. Production runs the Flask
application through Gunicorn. The application service exposes port 5000 to
Docker networks and does not directly publish that port on the host.

### SRI on embedded favicon

Excluded rule:

`html.security.audit.missing-integrity.missing-integrity`

The reported element is an SVG favicon embedded as a `data:` URI. It is not an
externally hosted script, stylesheet, or other remote dependency. Subresource
Integrity is therefore not applicable to that resource.

## Review principle

A Semgrep exclusion is not treated as proof that the underlying pattern is
universally safe. Each exclusion is scoped to the current architecture and
must be reconsidered if the corresponding transport, deployment model, or
resource loading strategy changes.
