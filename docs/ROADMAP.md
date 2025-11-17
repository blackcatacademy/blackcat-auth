# BlackCat Auth – Roadmap

## Stage 1 – Foundations ✅
- `config/example.auth.php` + `FoundationConfig` loader sdílí `${env:}` / `${file:}` placeholdery a `blackcat-config` profily, takže každý deployment používá stejné secrets/env.
- `AuthRuntime` + `UserStoreFactory` dávají dohromady DB-backed identitu (`users` tabulka dle `blackcat-database`), CLI `users:seed|users:list|security:check` a `bin/auth-http --config=...`.
- Telemetrie (`AuthTelemetry` + `TelemetryAuthHook`) produkuje Prometheus metriky (`blackcat_auth_events_*`), `security:check` validuje signing key, DB dostupnost a telemetry wiring.
- CLI `token:*`, `rbac:*`, `config:show`, `user:hash-password` používají stejný runtime jako HTTP server (seed users, DB provider, RBAC), testy pokrývají config loader + runtime seeding.

## Stage 2 – Flows & Extensibility ✅
- Password grant, refresh, client-credentials a PKCE helpery v `AuthManager` (`passwordGrant`, `clientCredentials`, `initiatePkce`, `exchangePkce`).
- `AuthEventHookInterface` + `LoggingAuthHook`, PKCE store (`PkceStoreInterface`, `InMemoryPkceStore`) a `ClientRegistry`.
- HTTP server (`bin/auth-http`) teď nabízí `/authorize` + `/token` podporující všechny granty.
- CLI rozšíření: `token:client`, `rbac:check`, `user:hash-password`, `token:issue` přijímá vlastní heslo.

## Stage 3 – Federation & SSO (in progress)
- ✅ OIDC discovery (`/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`) + `/jwks.json` (HS512 `oct` JWK, navázané na `BLACKCAT_AUTH_BASE_URL`).
- ✅ Základní session service (`BLACKCAT_AUTH_SESSION_TTL`, `/session` endpoints, `SessionService`) – další fáze přidá Redis/Postgres store, WebAuthn, remember-me cookies.
- ✅ Device-code flow (`/device/code`, `/device/activate`, `/device/token`) včetně pending/approved storage.
- ✅ Magic link + WebAuthn skeleton (magic-link request/consume, WebAuthn register/auth endpoints s in-memory credential store).
- Session service (redis/postgres) s rolling session IDs, remember-me cookies, WebAuthn production-grade store & attestation, magic-link throttling s hooking do email service.
- Outbound federation moduly (SAML, WS-Fed, OAuth Proxy) pro napojení enterprise IdP + inbound social loginy (GitHub, Google) přes stejné hooky.
- ✅ FE-friendly SDK – založen repo `blackcat-auth-js` s `AuthClient` (password/device code/magic link/WebAuthn).

## Stage 4 – Advanced RBAC & ABAC
- Deklarativní policy language (YAML/JSON) s podporou atributů (context, resource tags, risk levels), time-based a geo/region constraints. Kompatibilní s `blackcat-core/RBAC.php`.
- Multi-tenant RBAC registry s shadow policies, audit log stream do `blackcat-messaging`, cache invalidace přes `blackcat-database-sync`.
- Edge enforcement cache a policy-as-code tooling (`auth policy:lint`, `policy:bundle`) + integration test harness.

## Stage 5 – Observability & Zero Trust
- Telemetrie (Prometheus, OTLP traces), risk scoring/UEBA pipeline, adaptive auth (step-up, temporary lockouts) napojené na `StreamingAuthHook` + `/events/stream`.
- Service-mesh guardy (mTLS cert pinning, token binding) + SPDY/gRPC interceptory pro backend services.
- `auth-http` rozšířen o `/metrics`, `/events/stream` (SSE) a konfigurovatelné webhooky; CLI audit `auth watch` pro SecOps.

## Stage 6 – Identity Graph & Consent Hub (planned)
- Sdílená identity graph DB (uživatel ↔ zařízení ↔ org ↔ aplikace), napojení na `blackcat-identity` repo.
- Consent/versioning API, data residency policies a automatické obohacení claims (locale, feature-flags).
- GraphQL/REST endpointy a frontend kit (React hooks) pro komplexní profile/consent management, včetně offline sync do `blackcat-database-sync`.

(Repo se posunulo na Stage 2 ✅, pokračujeme ke Stage 3.)
