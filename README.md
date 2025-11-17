# BlackCat Auth

Komplexní autentizační a autorizační SDK pro platformu BlackCat. Cílem je nabídnout centrální logiku, aby frontend/edge služby nemusely vymýšlet vlastní tokeny, refresh mechanismy ani RBAC – vše jde přes `AuthManager` a přidružené služby.

## Klíčové vlastnosti

- **Více typů tokenů** – krátkodobé přístupové tokeny (JWT kompatibilní), refresh tokeny, servisní tokeny pro backend-backend komunikaci.
- **RBAC jádro** – `PolicyDecisionPoint` + `RoleRegistry` podporují role, skupiny i dynamické politiky (ABAC hooky).
- **Integrace s Crypto** – podpisy tokenů lze delegovat na `blackcat-crypto` (AEAD/HMAC). Pokud crypto není dostupné, fallback na lokální klíče.
- **IdentityProvider rozhraní** – snadno napojíš databázi, LDAP, OAuth brokera atd.
- **HTTP/CLI rozšíření** – vestavěný mini server (`auth-http`) pro testování login/refresh/PKCE/client-creds a CLI (`bin/auth`) pro vydávání tokenů, správu rolí, audit.
- **Password & email hashing** – `PasswordHasher` s pepper providerem a `DatabaseUserProvider` s pluggable EmailHasher (KeyManager/crypto friendly).
- **Front-end friendly** – hotové middleware/guards pro REST/GraphQL, rozhraní pro PKCE (S256/PLAIN), device-code a service-to-service flows.
- **Audit hooky & PKCE store** – `AuthEventHookInterface` umožňuje logovat každou autentizaci, `PkceStoreInterface` drží authorization codes s nastavitelným TTL.
- **OIDC discovery** – `/.well-known/openid-configuration` a `/jwks.json` staví metadata/JWKS automaticky z konfigurace (HS512 `oct` klíč, `jwks_uri`, granty…).
- **Device-code & session management** – `/device/*` endpoints s pending store a `/session` API pro rolling sessions (PDO/Redis store přes konfiguraci).

## Struktura

```
blackcat-auth/
├── src/
│   ├── AuthManager.php          # hlavní fasáda
│   ├── Config/                  # AuthConfig + env loader
│   ├── Token/                   # token service, JWT/JWE podpisy
│   ├── Rbac/                    # role, policy decision point
│   ├── Identity/                # IdentityProvider rozhraní
│   ├── Http/                    # jednoduchý HTTP server + middleware
│   ├── CLI/                     # příkazy pro správu
│   ├── Middleware/              # PSR-15 guardy
│   └── Support/                 # pomocné třídy (Clock, Encoder…)
├── docs/ROADMAP.md
├── README.md
├── composer.json
├── bin/auth
└── tests/
```

## Rychlý start

```bash
composer install
php bin/auth help
php bin/auth-http --port=8082
```

## Konfigurace & Foundation CLI (Stage 1)

- `config/example.auth.php` je kanonický vstup. Podporuje `${env:FOO}` / `${file:/path}` placeholdery a může načítat sdílené profily z `blackcat-config/config/profiles.php`. Doporučený způsob spuštění CLI je tedy vždy přes konfig:

```bash
export BLACKCAT_AUTH_SIGNING_KEY=$(openssl rand -base64 32)
export BLACKCAT_AUTH_PEPPER=$(openssl rand -base64 32)
php bin/auth config/example.auth.php config:show
```

- **Seed & správa uživatelů** – Stage 1 CLI přidává `users:seed`, `users:list`, `user:hash-password` a `token:*` příkazy, které používají databázový store (SQLite/MySQL/Postgres) přes `DatabaseUserProvider`. Stačí přizpůsobit `user_store` sekci v konfigu:

```bash
php bin/auth config/example.auth.php users:seed --force
php bin/auth config/example.auth.php users:list
php bin/auth config/example.auth.php token:issue --user=admin@example.com --password=secret
php bin/auth config/example.auth.php security:check
```

- **Telemetry & bezpečnost** – `telemetry.prom` soubor (viz `telemetry.prometheus_file`) se aktualizuje přes `TelemetryAuthHook`. `security:check` ověřuje délku signing key, dostupnost DB a zda je nastavena telemetry/pepper. `bin/auth-http --config=...` používá stejné konfigurační hodnoty + `UserStoreFactory` pro HTTP server, takže CLI/HTTP sdílí jednu konfiguraci.

- **Integrace na ostatní repa** – config podporuje `config_profile` (čte `blackcat-config`), `user_store` používá `blackcat-database` schéma (`users` tabulka) a signing key/pepper se běžně generují/uchovávají v `blackcat-crypto`. Stage 1 tak splňuje checklist: config loader, CLI vstupy (`config:show`, `users:list`, `token:*`), telemetry, security checks + docs/tests.

V aplikaci:

```php
use BlackCat\Auth\AuthManager;
use BlackCat\Auth\Config\AuthConfig;
use BlackCat\Auth\Identity\ArrayUserProvider;
use BlackCat\Auth\Password\PasswordHasher;
use BlackCat\Auth\Password\EnvPepperProvider;

$config = AuthConfig::fromEnv();
$provider = new ArrayUserProvider([
    ['id' => '1', 'email' => 'admin@example.com', 'password' => 'secret', 'roles' => ['admin']],
]);
$hasher = new PasswordHasher(new EnvPepperProvider());
$auth = AuthManager::boot($config, $provider);

$login = $auth->issueTokens('admin@example.com', 'secret');
$claims = $auth->verifyAccessToken($login->accessToken);
$auth->enforce('admin', $claims); // RBAC check
```

## Testy

```
composer test
```

## CLI

```
php bin/auth config/example.auth.php config:show
php bin/auth config/example.auth.php users:seed --force
php bin/auth config/example.auth.php users:list
php bin/auth config/example.auth.php token:issue --user=admin@example.com --password=secret
php bin/auth config/example.auth.php token:client --client=service-api --secret=supersecret
php bin/auth config/example.auth.php rbac:check --role=admin --claims='{"roles":["admin"]}'
php bin/auth config/example.auth.php user:hash-password --password="MyStrongPass"
```

## HTTP server

```
php bin/auth-http --config=config/example.auth.php --port=8082
```

Endpointy:

| Endpoint | Popis |
| --- | --- |
| `POST /login` | Password grant (`username`, `password`). |
| `POST /token` | OAuth-like token endpoint (`grant_type=password|refresh_token|client_credentials|authorization_code`). |
| `POST /authorize` | PKCE init (`client_id`, `username`, `password`, `code_challenge`, `code_challenge_method`). |
| `POST /introspect` | Ověření access tokenu / refresh tokenu. |
| `GET /healthz` | Základní health probe. |
| `GET /.well-known/openid-configuration` | OIDC discovery dokument (issuer, endpoints, granty). |
| `GET /jwks.json` | JWKS se seznamem klíčů (aktuálně `oct` pro HS512). |
| `GET /userinfo` | Vrátí claims aktuálního uživatele (vyžaduje Bearer token). |
| `POST /session` | Issuance session ID (Bearer token + volitelné context metadata). |
| `GET /session` | Výpis aktivních sessions aktuální identity. |
| `DELETE /session/{id}` | Zneplatní konkrétní session (pokud patří aktuálnímu subjektu). |
| `POST /device/code` | Vygeneruje device & user code pro offline zařízení. |
| `POST /device/activate` | Uživatelská aktivace – zadá `user_code` + přihlašovací údaje. |
| `POST /device/token` | Zařízení polluje, dokud nedostane access/refresh tokeny. |
| `POST /magic-link/request` | Vytvoří magic-link pro zadaný e-mail (dev odpověď obsahuje token + link). |
| `POST /magic-link/consume` | Spotřebuje magic-link token a vrací token pair. |
| `POST /webauthn/register/start` | (Bearer) Vrátí challenge pro registraci bezpečnostního klíče. |
| `POST /webauthn/register/finish` | (Bearer) Uloží credential. |
| `POST /webauthn/authenticate/start` | Spouští přihlášení – vrací challenge a allowed credential IDs. |
| `POST /webauthn/authenticate/finish` | Dokončí WebAuthn přihlášení, vrací token pair. |
| `GET /events/stream` | Vrací poslední auth události (`events` + `last_id`), vhodné pro SSE polling. |

## PKCE příklad

```php
$verifier = bin2hex(random_bytes(32));
$challenge = \BlackCat\Auth\Pkce\PkceHelper::challengeFromVerifier($verifier);
$code = $auth->initiatePkce('service-api', 'admin@example.com', 'secret', $challenge);
$tokens = $auth->exchangePkce('service-api', $code, $verifier);
```

## Session service

```php
use BlackCat\Auth\Session\SessionService;
use BlackCat\Auth\Session\InMemorySessionStore;

$sessions = new SessionService(new InMemorySessionStore(), 60 * 60 * 24 * 14); // 14 dní
$auth = $auth->withSessionService($sessions);
$pair = $auth->issueTokens('admin@example.com', 'secret');
$session = $auth->issueSession($auth->verifyAccessToken($pair->accessToken), ['ip' => '127.0.0.1']);
```

Pro produkci nastav `BLACKCAT_AUTH_SESSION_TTL` a `BLACKCAT_AUTH_SESSION_STORE` (např. `{"type":"pdo","dsn":"pgsql:host=db;dbname=auth","table":"auth_sessions"}` nebo `{"type":"redis","uri":"tcp://redis:6379","prefix":"auth:sessions"}`) – `auth-http` pak použije perzistentní storage.

## Device code flow

```bash
# 1) Zařízení (bez klávesnice) požádá o kód
curl -X POST http://localhost:8082/device/code -d '{"client_id":"device-client","scope":"openid"}'

# 2) Zobrazí se user_code a verification_uri -> uživatel otevře /device/activate
# 3) Aktivace
curl -X POST http://localhost:8082/device/activate -d '{"user_code":"ABCD1234","username":"demo@example.com","password":"secret"}'

# 4) Zařízení polluje
curl -X POST http://localhost:8082/device/token -d '{"device_code":"<device_code>"}'
```

## Magic link

```bash
# 1) Požádej o magic link
curl -X POST http://localhost:8082/magic-link/request \
     -H "Content-Type: application/json" \
     -d '{"email":"demo@example.com","redirect":"/dashboard"}'

# 2) V ostrém prostředí odejde e-mail; v dev výstupu je `token` a `link`

# 3) Uživatelský klient odešle token
curl -X POST http://localhost:8082/magic-link/consume \
     -H "Content-Type: application/json" \
     -d '{"token":"<token>"}'
```

Magic link TTL nastav `BLACKCAT_AUTH_MAGICLINK_TTL` (sekundy) a `BLACKCAT_AUTH_MAGICLINK_URL` (frontend stránka, která token spotřebuje). `auth-http` prozatím vrací token/link přímo, aby se daly snadno testovat.

## Event stream / Observability

`auth-http` udržuje kruhový buffer auditních událostí (výchozí 200 položek, nastav `BLACKCAT_AUTH_EVENTS_BUFFER`). Endpoint `/events/stream?last_id=123` vrací JSON:

```json
{
  "last_id": 42,
  "events": [
    {"id": 41, "event": "password_grant", "payload": {"username": "demo@example.com","result":"success"}, "timestamp": 1710000000}
  ]
}
```

Pro SSE-like chování klient periodicky volá endpoint s `last_id` a doručuje jen nové položky. Velikost bufferu nastav `BLACKCAT_AUTH_EVENTS_BUFFER`.

Audity snadno přepošleš do observability vrstvy:

```php
use BlackCat\Auth\Support\StreamingAuthHook;
use BlackCat\Observability\ObservabilityManager;

$obs = ObservabilityManager::boot();
$hook = new StreamingAuthHook(fn($event, $payload) => $obs->events()->publish('auth.' . $event, $payload));
$auth = AuthManager::boot($config, $provider, logger: null, hook: $hook);
```

## WebAuthn (Passkeys)

```bash
# Registrace (uživatel musí mít Bearer token)
curl -H "Authorization: Bearer <token>" -X POST http://localhost:8082/webauthn/register/start
curl -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
     -d '{"challenge":"...","credential_id":"cred-1","public_key":"base64public"}' \
     http://localhost:8082/webauthn/register/finish

# Přihlášení
curl -X POST http://localhost:8082/webauthn/authenticate/start -d '{"email":"demo@example.com"}'
curl -X POST http://localhost:8082/webauthn/authenticate/finish \
     -H "Content-Type: application/json" \
     -d '{"email":"demo@example.com","challenge":"...","credential_id":"cred-1"}'
```

Pro aktivaci nastav `BLACKCAT_AUTH_WEBAUTHN_RP_ID` (např. `auth.example.com`) a `BLACKCAT_AUTH_WEBAUTHN_RP_NAME` (zobrazované jméno). Implementace zatím uchovává credentialy v paměti – pro produkci je potřeba vlastní store (Redis/DB).

## Audit hooky

```php
use BlackCat\Auth\Support\LoggingAuthHook;
$logger = new \Monolog\Logger('auth');
$auth = AuthManager::boot($config, $provider, $logger, null, new LoggingAuthHook($logger));
```

Konfigurační proměnná `BLACKCAT_AUTH_EVENT_WEBHOOKS` (JSON list URL) umožňuje zároveň odesílat události na externí webhooks (POST JSON).

## Konfigurace (env)

- `BLACKCAT_AUTH_ROLES` – JSON definice rolí/permissions.
- `BLACKCAT_AUTH_CLIENTS` – JSON map (`client_id` => `{secret,roles,scopes,access_ttl,pkce}`).
- `BLACKCAT_AUTH_PKCE_TTL` – TTL pro authorization codes (sekundy, default 300).
- `BLACKCAT_AUTH_USERS` – JSON fallback uživatelů pro `auth-http` (pokud nepoužívá DB).
- `BLACKCAT_AUTH_DB_DSN` (+ `_USER`, `_PASS`, `_TABLE`, `_EMAIL_COLUMN`, `_PASSWORD_COLUMN`, `_ROLES_COLUMN`) – aktivuje `DatabaseUserProvider` v `auth-http`.
- `BLACKCAT_AUTH_HTTP_PORT` – implicitní port HTTP serveru.
- `BLACKCAT_AUTH_BASE_URL` – veřejná URL použitá pro OIDC discovery endpoints (`https://auth.example.com`).
- `BLACKCAT_AUTH_SESSION_TTL` – pokud je > 0, aktivuje session service (`/session` endpointy) s daným TTL v sekundách.
- `BLACKCAT_AUTH_SESSION_STORE` – JSON konfigurace session storage (`{"type":"pdo","dsn":"sqlite:/var/auth_sessions.db"}` nebo `{"type":"redis","uri":"tcp://redis:6379","prefix":"myapp:sessions"}`).
- `BLACKCAT_AUTH_MAGICLINK_TTL` – TTL pro magic link tokeny (sekundy).
- `BLACKCAT_AUTH_MAGICLINK_URL` – veřejná URL kam se má magic link směrovat (např. `https://app.example.com/magic-login`).
- `BLACKCAT_AUTH_WEBAUTHN_RP_ID` / `BLACKCAT_AUTH_WEBAUTHN_RP_NAME` – aktivuje WebAuthn endpoints (RP ID/Name).
- `BLACKCAT_AUTH_EVENTS_BUFFER` – velikost kruhového bufferu pro `/events/stream` (default 200).
- `BLACKCAT_AUTH_EVENT_WEBHOOKS` – JSON seznam webhook URL, kam se posílají audit eventy.

## Další kroky

- Roadmapa je v `docs/ROADMAP.md`.
- `auth-http` poslouží jako referenční server pro testování grantů; `bin/auth` obsahuje i audit/telemetrické helpery (viz nové příkazy).
