<?php
declare(strict_types=1);

namespace BlackCat\Auth\Config;

final class AuthConfig
{
    public function __construct(
        private readonly string $issuer,
        private readonly string $audience,
        private readonly string $signingKey,
        private readonly int $accessTtl,
        private readonly int $refreshTtl,
        private readonly array $roles = [],
        private readonly array $clients = [],
        private readonly int $pkceWindow = 300,
        private readonly string $publicBaseUrl = '',
        private readonly ?int $sessionTtl = null,
        private readonly array $sessionStore = [],
        private readonly ?int $magicLinkTtl = null,
        private readonly string $magicLinkUrl = '',
        private readonly ?string $webauthnRpId = null,
        private readonly ?string $webauthnRpName = null,
        private readonly int $eventsBufferSize = 200,
        private readonly array $eventWebhooks = [],
    ) {}

    public static function fromEnv(array $env = []): self
    {
        $env = $env ?: $_ENV + $_SERVER;
        $issuer = (string)($env['BLACKCAT_AUTH_ISSUER'] ?? 'blackcat-auth');
        $audience = (string)($env['BLACKCAT_AUTH_AUDIENCE'] ?? 'blackcat-clients');
        $signingKey = (string)($env['BLACKCAT_AUTH_KEY'] ?? base64_encode(random_bytes(32)));
        $access = (int)($env['BLACKCAT_AUTH_ACCESS_TTL'] ?? 900);
        $refresh = (int)($env['BLACKCAT_AUTH_REFRESH_TTL'] ?? 604800);
        $roles = json_decode($env['BLACKCAT_AUTH_ROLES'] ?? '[]', true) ?: [];
        $clients = json_decode($env['BLACKCAT_AUTH_CLIENTS'] ?? '[]', true) ?: [];
        $pkceWindow = (int)($env['BLACKCAT_AUTH_PKCE_TTL'] ?? 300);
        $baseUrl = (string)($env['BLACKCAT_AUTH_BASE_URL'] ?? $issuer);
        $sessionTtl = isset($env['BLACKCAT_AUTH_SESSION_TTL']) ? (int)$env['BLACKCAT_AUTH_SESSION_TTL'] : null;
        $sessionStore = json_decode($env['BLACKCAT_AUTH_SESSION_STORE'] ?? '[]', true) ?: [];
        $magicLinkTtl = isset($env['BLACKCAT_AUTH_MAGICLINK_TTL']) ? (int)$env['BLACKCAT_AUTH_MAGICLINK_TTL'] : null;
        $magicLinkUrl = (string)($env['BLACKCAT_AUTH_MAGICLINK_URL'] ?? ($baseUrl . '/magic-login'));
        $webauthnRpId = $env['BLACKCAT_AUTH_WEBAUTHN_RP_ID'] ?? null;
        $webauthnRpName = $env['BLACKCAT_AUTH_WEBAUTHN_RP_NAME'] ?? null;
        $eventsBuffer = isset($env['BLACKCAT_AUTH_EVENTS_BUFFER']) ? max(10, (int)$env['BLACKCAT_AUTH_EVENTS_BUFFER']) : 200;
        $eventWebhooks = json_decode($env['BLACKCAT_AUTH_EVENT_WEBHOOKS'] ?? '[]', true) ?: [];
        return new self(
            $issuer,
            $audience,
            $signingKey,
            $access,
            $refresh,
            $roles,
            $clients,
            max(60, $pkceWindow),
            rtrim($baseUrl, '/'),
            $sessionTtl && $sessionTtl > 0 ? $sessionTtl : null,
            $sessionStore,
            $magicLinkTtl && $magicLinkTtl > 0 ? $magicLinkTtl : null,
            rtrim($magicLinkUrl, '/'),
            $webauthnRpId ? strtolower(trim($webauthnRpId)) : null,
            $webauthnRpName ? trim($webauthnRpName) : null,
            $eventsBuffer,
            array_values(array_filter(array_map(static fn($url) => is_string($url) ? trim($url) : null, $eventWebhooks))),
        );
    }

    public function issuer(): string { return $this->issuer; }
    public function audience(): string { return $this->audience; }
    public function signingKey(): string { return $this->signingKey; }
    public function accessTtl(): int { return $this->accessTtl; }
    public function refreshTtl(): int { return $this->refreshTtl; }
    public function roles(): array { return $this->roles; }
    public function clients(): array { return $this->clients; }
    public function pkceWindow(): int { return $this->pkceWindow; }
    public function publicBaseUrl(): string
    {
        return $this->publicBaseUrl ?: $this->issuer;
    }

    public function sessionTtl(): ?int
    {
        return $this->sessionTtl;
    }

    /** @return array<string,mixed> */
    public function sessionStoreConfig(): array
    {
        return $this->sessionStore;
    }

    public function magicLinkTtl(): ?int
    {
        return $this->magicLinkTtl;
    }

    public function magicLinkUrl(): string
    {
        return $this->magicLinkUrl ?: ($this->publicBaseUrl . '/magic-login');
    }

    public function webauthnRpId(): ?string
    {
        return $this->webauthnRpId;
    }

    public function webauthnRpName(): ?string
    {
        return $this->webauthnRpName;
    }

    public function eventsBufferSize(): int
    {
        return $this->eventsBufferSize;
    }

    /**
     * @return list<string>
     */
    public function eventWebhooks(): array
    {
        return $this->eventWebhooks;
    }
}
