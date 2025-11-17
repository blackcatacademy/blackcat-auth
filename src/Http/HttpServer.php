<?php
declare(strict_types=1);

namespace BlackCat\Auth\Http;

use BlackCat\Auth\AuthManager;
use BlackCat\Auth\Config\AuthConfig;
use BlackCat\Auth\Identity\IdentityProviderInterface;
use BlackCat\Auth\Token\TokenPair;
use BlackCat\Auth\Support\JwksProvider;
use BlackCat\Auth\Support\OidcMetadataBuilder;
use BlackCat\Auth\DeviceCode\DeviceCodeService;
use BlackCat\Auth\DeviceCode\InMemoryDeviceCodeStore;
use BlackCat\Auth\Session\SessionService;
use BlackCat\Auth\Session\SessionStoreFactory;
use BlackCat\Auth\Session\InMemorySessionStore;
use BlackCat\Auth\MagicLink\MagicLinkService;
use BlackCat\Auth\MagicLink\InMemoryMagicLinkStore;
use BlackCat\Auth\WebAuthn\WebAuthnService;
use BlackCat\Auth\WebAuthn\InMemoryWebAuthnStore;
use BlackCat\Auth\Support\CompositeAuthHook;
use BlackCat\Auth\Support\EventBuffer;
use BlackCat\Auth\Support\StreamingAuthHook;
use BlackCat\Auth\Support\TelemetryAuthHook;
use BlackCat\Auth\Support\WebhookEventHook;
use BlackCat\Auth\Telemetry\AuthTelemetry;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class HttpServer
{
    public function __construct(
        private readonly AuthManager $auth,
        private readonly AuthConfig $config,
        private readonly LoggerInterface $logger = new NullLogger(),
        private readonly ?SessionService $sessions = null,
        private readonly ?DeviceCodeService $deviceCodes = null,
        private readonly ?MagicLinkService $magicLinks = null,
        private readonly ?WebAuthnService $webauthn = null,
        private readonly ?EventBuffer $events = null,
    ) {}

    public static function bootstrap(
        AuthConfig $config,
        IdentityProviderInterface $provider,
        ?LoggerInterface $logger = null,
        ?SessionService $sessionService = null,
        ?DeviceCodeService $deviceCodeService = null,
        ?MagicLinkService $magicLinkService = null,
        ?WebAuthnService $webauthnService = null,
        ?AuthTelemetry $telemetry = null,
    ): self {
        $eventsBuffer = new EventBuffer($config->eventsBufferSize());
        $hooks = [];
        $telemetry ??= new AuthTelemetry(null);
        $hooks[] = new TelemetryAuthHook($telemetry);
        $hooks[] = new StreamingAuthHook(fn(string $event, array $payload) => $eventsBuffer->push($event, $payload));
        if ($config->eventWebhooks()) {
            $hooks[] = new WebhookEventHook($config->eventWebhooks());
        }
        $hook = count($hooks) === 1 ? $hooks[0] : new CompositeAuthHook(...$hooks);
        $auth = AuthManager::boot($config, $provider, $logger, null, $hook);
        if ($sessionService === null && $config->sessionTtl()) {
            $storeConfig = $config->sessionStoreConfig();
            $store = $storeConfig ? SessionStoreFactory::fromConfig($storeConfig) : new InMemorySessionStore();
            $sessionService = new SessionService($store, $config->sessionTtl());
        }
        if ($sessionService) {
            $auth = $auth->withSessionService($sessionService);
        }
        if ($magicLinkService === null && $config->magicLinkTtl()) {
            $magicLinkService = new MagicLinkService(
                new InMemoryMagicLinkStore(),
                $config->magicLinkTtl(),
                $config->magicLinkUrl(),
                $config->signingKey()
            );
        }
        if ($magicLinkService) {
            $auth = $auth->withMagicLinkService($magicLinkService);
        }
        $webauthnService ??= $config->webauthnRpId()
            ? new WebAuthnService(
                new InMemoryWebAuthnStore(),
                $config->webauthnRpId(),
                $config->webauthnRpName() ?? 'BlackCat Auth'
            )
            : null;
        $deviceCodeService ??= new DeviceCodeService(
            new InMemoryDeviceCodeStore(),
            rtrim($config->publicBaseUrl(), '/') . '/device/activate'
        );
        return new self($auth, $config, $logger ?? new NullLogger(), $sessionService, $deviceCodeService, $magicLinkService, $webauthnService, $eventsBuffer);
    }

    public function handle(array $request): array
    {
        $path = $request['path'] ?? '';
        return match ($path) {
            '/login' => $this->login($request),
            '/refresh' => $this->refresh($request),
            '/introspect' => $this->introspect($request),
            '/jwks.json' => ['status' => 200, 'body' => JwksProvider::fromConfig($this->config)],
            '/.well-known/openid-configuration' => ['status' => 200, 'body' => OidcMetadataBuilder::build($this->config)],
            '/.well-known/oauth-authorization-server' => ['status' => 200, 'body' => OidcMetadataBuilder::build($this->config)],
            '/userinfo' => $this->userinfo($request),
            '/authorize' => $this->authorize($request),
            '/token' => $this->token($request),
            '/session' => $this->handleSessionCollection($request),
            '/device/code' => $this->deviceCodeIssue($request),
            '/device/activate' => $this->deviceCodeActivate($request),
            '/device/token' => $this->deviceCodePoll($request),
            '/magic-link/request' => $this->magicLinkRequest($request),
            '/magic-link/consume' => $this->magicLinkConsume($request),
            '/webauthn/register/start' => $this->webauthnRegisterStart($request),
            '/webauthn/register/finish' => $this->webauthnRegisterFinish($request),
            '/webauthn/authenticate/start' => $this->webauthnAuthStart($request),
            '/webauthn/authenticate/finish' => $this->webauthnAuthFinish($request),
            '/events/stream' => $this->eventsStream($request),
            '/healthz' => ['status' => 200, 'body' => ['status' => 'ok']],
            default => $this->handleDynamicRoutes($path, $request),
        };
    }

    private function login(array $request): array
    {
        $body = $request['body'] ?? [];
        $email = (string)($body['username'] ?? '');
        $password = (string)($body['password'] ?? '');
        try {
            $tokens = $this->auth->issueTokens($email, $password);
            return ['status' => 200, 'body' => $this->formatPair($tokens)];
        } catch (\Throwable $e) {
            return ['status' => 401, 'body' => ['error' => 'invalid_credentials']];
        }
    }

    private function refresh(array $request): array
    {
        $body = $request['body'] ?? [];
        $token = (string)($body['refresh_token'] ?? '');
        try {
            $tokens = $this->auth->refresh($token);
            return ['status' => 200, 'body' => $this->formatPair($tokens)];
        } catch (\Throwable $e) {
            return ['status' => 401, 'body' => ['error' => $e->getMessage()]];
        }
    }

    private function introspect(array $request): array
    {
        $body = $request['body'] ?? [];
        $token = (string)($body['token'] ?? '');
        try {
            $claims = $this->auth->verifyAccessToken($token);
            return ['status' => 200, 'body' => ['active' => true, 'claims' => $claims]];
        } catch (\Throwable $e) {
            return ['status' => 200, 'body' => ['active' => false, 'error' => $e->getMessage()]];
        }
    }

    private function authorize(array $request): array
    {
        $body = $request['body'] ?? [];
        try {
            $code = $this->auth->initiatePkce(
                (string)($body['client_id'] ?? ''),
                (string)($body['username'] ?? ''),
                (string)($body['password'] ?? ''),
                (string)($body['code_challenge'] ?? ''),
                (string)($body['code_challenge_method'] ?? 'S256'),
                (array)($body['scopes'] ?? [])
            );
            return ['status' => 200, 'body' => ['code' => $code]];
        } catch (\Throwable $e) {
            return ['status' => 400, 'body' => ['error' => $e->getMessage()]];
        }
    }

    private function token(array $request): array
    {
        $body = $request['body'] ?? [];
        $grant = strtolower((string)($body['grant_type'] ?? 'password'));
        try {
            return match ($grant) {
                'password' => ['status' => 200, 'body' => $this->formatPair(
                    $this->auth->passwordGrant(
                        (string)($body['username'] ?? ''),
                        (string)($body['password'] ?? ''),
                        []
                    )
                )],
                'refresh_token' => ['status' => 200, 'body' => $this->formatPair(
                    $this->auth->refresh((string)($body['refresh_token'] ?? ''))
                )],
                'client_credentials' => ['status' => 200, 'body' => $this->formatPair(
                    $this->auth->clientCredentials(
                        (string)($body['client_id'] ?? ''),
                        (string)($body['client_secret'] ?? ''),
                        (array)($body['scopes'] ?? [])
                    )
                )],
                'authorization_code' => ['status' => 200, 'body' => $this->formatPair(
                    $this->auth->exchangePkce(
                        (string)($body['client_id'] ?? ''),
                        (string)($body['code'] ?? ''),
                        (string)($body['code_verifier'] ?? '')
                    )
                )],
                default => ['status' => 400, 'body' => ['error' => 'unsupported_grant_type']],
            };
        } catch (\Throwable $e) {
            return ['status' => 400, 'body' => ['error' => $e->getMessage()]];
        }
    }

    private function formatPair(TokenPair $pair): array
    {
        return [
            'access_token' => $pair->accessToken,
            'refresh_token' => $pair->refreshToken,
            'expires_at' => $pair->expiresAt,
        ];
    }

    private function userinfo(array $request): array
    {
        [$claims, $error] = $this->claimsFromRequest($request);
        if ($error !== null) {
            return $error;
        }
        $allowed = [
            'sub' => $claims['sub'] ?? null,
            'email' => $claims['email'] ?? null,
            'name' => $claims['name'] ?? ($claims['email'] ?? null),
            'roles' => $claims['roles'] ?? [],
            'scopes' => $claims['scopes'] ?? [],
        ];
        return ['status' => 200, 'body' => array_filter($allowed, static fn($value) => $value !== null)];
    }

    private function handleSessionCollection(array $request): array
    {
        $method = strtoupper((string)($request['method'] ?? 'GET'));
        return match ($method) {
            'POST' => $this->sessionIssue($request),
            'GET' => $this->sessionList($request),
            default => ['status' => 405, 'body' => ['error' => 'method_not_allowed']],
        };
    }

    private function handleDynamicRoutes(string $path, array $request): array
    {
        if (preg_match('~^/session/([^/]+)$~', $path, $match)) {
            $method = strtoupper((string)($request['method'] ?? 'GET'));
            if ($method === 'DELETE') {
                return $this->sessionDelete($request, $match[1]);
            }
            return ['status' => 405, 'body' => ['error' => 'method_not_allowed']];
        }
        return ['status' => 404, 'body' => ['error' => 'not-found']];
    }

    private function sessionIssue(array $request): array
    {
        if (!$this->auth->sessionService()) {
            return ['status' => 501, 'body' => ['error' => 'sessions_disabled']];
        }
        [$claims, $error] = $this->claimsFromRequest($request);
        if ($error !== null) {
            return $error;
        }
        $context = (array)($request['body']['context'] ?? []);
        $session = $this->auth->issueSession($claims, $context);
        return ['status' => 201, 'body' => [
            'session_id' => $session->id,
            'subject' => $session->subject,
            'expires_at' => $session->expiresAt,
            'context' => $session->context,
        ]];
    }

    private function sessionList(array $request): array
    {
        $service = $this->auth->sessionService();
        if (!$service) {
            return ['status' => 501, 'body' => ['error' => 'sessions_disabled']];
        }
        [$claims, $error] = $this->claimsFromRequest($request);
        if ($error !== null) {
            return $error;
        }
        $sessions = $service->sessionsFor((string)($claims['sub'] ?? ''));
        return ['status' => 200, 'body' => array_map(fn($session) => [
            'session_id' => $session->id,
            'issued_at' => $session->issuedAt,
            'expires_at' => $session->expiresAt,
            'context' => $session->context,
        ], $sessions)];
    }

    private function sessionDelete(array $request, string $sessionId): array
    {
        $service = $this->auth->sessionService();
        if (!$service) {
            return ['status' => 501, 'body' => ['error' => 'sessions_disabled']];
        }
        [$claims, $error] = $this->claimsFromRequest($request);
        if ($error !== null) {
            return $error;
        }
        $session = $service->validate($sessionId);
        if ($session === null) {
            return ['status' => 404, 'body' => ['error' => 'session_not_found']];
        }
        if ($session->subject !== ($claims['sub'] ?? null)) {
            return ['status' => 403, 'body' => ['error' => 'forbidden']];
        }
        $service->revoke($sessionId);
        return ['status' => 204, 'body' => []];
    }

    /**
     * @return array{0:?array,1:?array}
     */
    private function claimsFromRequest(array $request): array
    {
        $token = $this->extractBearer($request);
        if (!$token) {
            return [null, ['status' => 401, 'body' => ['error' => 'missing_token']]];
        }
        try {
            return [$this->auth->verifyAccessToken($token), null];
        } catch (\Throwable $e) {
            return [null, ['status' => 401, 'body' => ['error' => $e->getMessage()]]];
        }
    }

    private function extractBearer(array $request): ?string
    {
        $headers = $request['headers'] ?? [];
        $auth = $headers['Authorization'] ?? $headers['authorization'] ?? null;
        if (!$auth || !str_starts_with($auth, 'Bearer ')) {
            return null;
        }
        return substr($auth, 7);
    }

    private function deviceCodeIssue(array $request): array
    {
        if (!$this->deviceCodes) {
            return ['status' => 501, 'body' => ['error' => 'device_code_disabled']];
        }
        $body = $request['body'] ?? [];
        $clientId = (string)($body['client_id'] ?? '');
        if ($clientId === '' || !$this->auth->hasClient($clientId)) {
            return ['status' => 400, 'body' => ['error' => 'invalid_client']];
        }
        $scopes = $this->parseScopes((string)($body['scope'] ?? ''));
        $payload = $this->deviceCodes->issue($clientId, $scopes);
        return ['status' => 200, 'body' => $payload];
    }

    private function deviceCodeActivate(array $request): array
    {
        if (!$this->deviceCodes) {
            return ['status' => 501, 'body' => ['error' => 'device_code_disabled']];
        }
        $body = $request['body'] ?? [];
        $userCode = (string)($body['user_code'] ?? '');
        $username = (string)($body['username'] ?? '');
        $password = (string)($body['password'] ?? '');
        if ($userCode === '' || $username === '' || $password === '') {
            return ['status' => 400, 'body' => ['error' => 'invalid_request']];
        }
        try {
            $pair = $this->auth->passwordGrant($username, $password);
        } catch (\Throwable $e) {
            return ['status' => 401, 'body' => ['error' => 'invalid_credentials']];
        }
        $result = $this->deviceCodes->approve($userCode, $this->formatPair($pair));
        if ($result['status'] === 'approved') {
            return ['status' => 200, 'body' => ['status' => 'approved']];
        }
        return ['status' => 400, 'body' => ['error' => $result['error'] ?? 'invalid_grant']];
    }

    private function deviceCodePoll(array $request): array
    {
        if (!$this->deviceCodes) {
            return ['status' => 501, 'body' => ['error' => 'device_code_disabled']];
        }
        $body = $request['body'] ?? [];
        $deviceCode = (string)($body['device_code'] ?? '');
        if ($deviceCode === '') {
            return ['status' => 400, 'body' => ['error' => 'invalid_request']];
        }
        $result = $this->deviceCodes->poll($deviceCode);
        return match ($result['status']) {
            'approved' => ['status' => 200, 'body' => $result['tokens']],
            'pending' => ['status' => 400, 'body' => ['error' => $result['error']]],
            default => ['status' => 400, 'body' => ['error' => $result['error'] ?? 'invalid_grant']],
        };
    }

    private function magicLinkRequest(array $request): array
    {
        if (!$this->magicLinks) {
            return ['status' => 501, 'body' => ['error' => 'magic_link_disabled']];
        }
        $body = $request['body'] ?? [];
        $email = (string)($body['email'] ?? '');
        if ($email === '') {
            return ['status' => 400, 'body' => ['error' => 'invalid_request']];
        }
        $identity = $this->auth->findIdentityByEmail($email);
        if ($identity === null) {
            return ['status' => 404, 'body' => ['error' => 'user_not_found']];
        }
        $context = [];
        if (!empty($body['redirect'])) {
            $context['redirect'] = (string)$body['redirect'];
        }
        $issued = $this->magicLinks->issue((string)($identity['id'] ?? ''), $context);
        // TODO: fire notification/email hook. For now return link/token for development/testing.
        return ['status' => 200, 'body' => [
            'status' => 'sent',
            'expires_at' => $issued['expires_at'],
            'link' => $issued['link'],
            'token' => $issued['token'],
        ]];
    }

    private function magicLinkConsume(array $request): array
    {
        if (!$this->magicLinks) {
            return ['status' => 501, 'body' => ['error' => 'magic_link_disabled']];
        }
        $token = (string)($request['body']['token'] ?? '');
        if ($token === '') {
            return ['status' => 400, 'body' => ['error' => 'invalid_request']];
        }
        $payload = $this->magicLinks->consume($token);
        if ($payload === null) {
            return ['status' => 400, 'body' => ['error' => 'invalid_or_expired_magic_link']];
        }
        $identity = $this->auth->findIdentityById($payload['subject']);
        if ($identity === null) {
            return ['status' => 404, 'body' => ['error' => 'user_not_found']];
        }
        $pair = $this->auth->issueForIdentity($identity);
        $response = $this->formatPair($pair);
        if ($payload['context']) {
            $response['context'] = $payload['context'];
        }
        return ['status' => 200, 'body' => $response];
    }

    private function webauthnRegisterStart(array $request): array
    {
        if (!$this->webauthn) {
            return ['status' => 501, 'body' => ['error' => 'webauthn_disabled']];
        }
        [$claims, $error] = $this->claimsFromRequest($request);
        if ($error !== null) {
            return $error;
        }
        $subject = (string)($claims['sub'] ?? '');
        if ($subject === '') {
            return ['status' => 400, 'body' => ['error' => 'invalid_subject']];
        }
        $options = $this->webauthn->startRegistration($subject);
        return ['status' => 200, 'body' => $options];
    }

    private function webauthnRegisterFinish(array $request): array
    {
        if (!$this->webauthn) {
            return ['status' => 501, 'body' => ['error' => 'webauthn_disabled']];
        }
        [$claims, $error] = $this->claimsFromRequest($request);
        if ($error !== null) {
            return $error;
        }
        $body = $request['body'] ?? [];
        $subject = (string)($claims['sub'] ?? '');
        $challenge = (string)($body['challenge'] ?? '');
        $credentialId = (string)($body['credential_id'] ?? '');
        $publicKey = (string)($body['public_key'] ?? '');
        if ($subject === '' || $challenge === '' || $credentialId === '' || $publicKey === '') {
            return ['status' => 400, 'body' => ['error' => 'invalid_request']];
        }
        $ok = $this->webauthn->finishRegistration($subject, $challenge, $credentialId, $publicKey);
        return $ok ? ['status' => 200, 'body' => ['status' => 'registered']] : ['status' => 400, 'body' => ['error' => 'invalid_challenge']];
    }

    private function webauthnAuthStart(array $request): array
    {
        if (!$this->webauthn) {
            return ['status' => 501, 'body' => ['error' => 'webauthn_disabled']];
        }
        $email = (string)($request['body']['email'] ?? '');
        if ($email === '') {
            return ['status' => 400, 'body' => ['error' => 'invalid_request']];
        }
        $identity = $this->auth->findIdentityByEmail($email);
        if ($identity === null) {
            return ['status' => 404, 'body' => ['error' => 'user_not_found']];
        }
        $options = $this->webauthn->startAuthentication((string)$identity['id']);
        if ($options === null) {
            return ['status' => 400, 'body' => ['error' => 'no_credentials']];
        }
        return ['status' => 200, 'body' => $options + ['user_id' => (string)$identity['id']]];
    }

    private function webauthnAuthFinish(array $request): array
    {
        if (!$this->webauthn) {
            return ['status' => 501, 'body' => ['error' => 'webauthn_disabled']];
        }
        $body = $request['body'] ?? [];
        $email = (string)($body['email'] ?? '');
        $challenge = (string)($body['challenge'] ?? '');
        $credentialId = (string)($body['credential_id'] ?? '');
        if ($email === '' || $challenge === '' || $credentialId === '') {
            return ['status' => 400, 'body' => ['error' => 'invalid_request']];
        }
        $identity = $this->auth->findIdentityByEmail($email);
        if ($identity === null) {
            return ['status' => 404, 'body' => ['error' => 'user_not_found']];
        }
        $subject = (string)($identity['id'] ?? '');
        $valid = $this->webauthn->finishAuthentication($subject, $challenge, $credentialId);
        if (!$valid) {
            return ['status' => 400, 'body' => ['error' => 'invalid_challenge']];
        }
        $pair = $this->auth->issueForIdentity($identity);
        return ['status' => 200, 'body' => $this->formatPair($pair)];
    }

    /**
     * @return list<string>
     */
    private function parseScopes(string $scope): array
    {
        $parts = preg_split('/\s+/', trim($scope)) ?: [];
        return array_values(array_filter($parts, fn($value) => $value !== ''));
    }

    private function eventsStream(array $request): array
    {
        if ($this->events === null) {
            return ['status' => 501, 'body' => ['error' => 'events_disabled']];
        }
        $query = $request['query'] ?? [];
        $lastId = isset($query['last_id']) ? (int)$query['last_id'] : null;
        $events = $this->events->history($lastId);
        return [
            'status' => 200,
            'body' => [
                'last_id' => $this->events->lastId(),
                'events' => $events,
            ],
        ];
    }
}
