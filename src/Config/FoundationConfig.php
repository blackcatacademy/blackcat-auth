<?php
declare(strict_types=1);

namespace BlackCat\Auth\Config;

use InvalidArgumentException;

final class FoundationConfig
{
    /** @var array<string,mixed> */
    private array $payload;

    private function __construct(private readonly array $resolved, private readonly string $path)
    {
        $this->payload = $resolved;
    }

    public static function fromFile(string $path): self
    {
        if (!is_file($path)) {
            throw new InvalidArgumentException("Auth foundation config missing: {$path}");
        }
        $data = require $path;
        if (!is_array($data)) {
            throw new InvalidArgumentException('Auth foundation config must return array');
        }
        $profileEnv = self::loadProfileEnv($data);
        $resolved = self::resolve($data, $profileEnv);
        return new self($resolved, $path);
    }

    public function path(): string
    {
        return $this->path;
    }

    public function directory(): string
    {
        return dirname($this->path);
    }

    public function authConfig(): AuthConfig
    {
        return AuthConfig::fromEnv($this->buildEnvPayload());
    }

    /**
     * @return array<string,mixed>
     */
    public function userStore(): array
    {
        return $this->payload['user_store'] ?? [];
    }

    /**
     * @return list<array<string,mixed>>
     */
    public function seedUsers(): array
    {
        $users = $this->payload['seed_users'] ?? [];
        if (!is_array($users)) {
            return [];
        }
        return array_values(array_filter(array_map(static function ($row) {
            return is_array($row) ? $row : null;
        }, $users)));
    }

    public function telemetryFile(): ?string
    {
        $file = $this->payload['telemetry']['prometheus_file'] ?? null;
        return $file ? (string) $file : null;
    }

    /**
     * @return array<string,mixed>
     */
    public function cliDefaults(): array
    {
        $cli = $this->payload['cli'] ?? [];
        return is_array($cli) ? $cli : [];
    }

    /**
     * @param mixed $value
     * @param array<string,string> $profileEnv
     * @return mixed
     */
    private static function resolve(mixed $value, array $profileEnv): mixed
    {
        if (is_string($value)) {
            if (preg_match('/^\$\{env:([^}]+)}/', $value, $envMatch)) {
                $envKey = $envMatch[1];
                return $profileEnv[$envKey] ?? getenv($envKey) ?: '';
            }
            if (preg_match('/^\$\{file:([^}]+)}/', $value, $fileMatch)) {
                $filePath = $fileMatch[1];
                return is_file($filePath) ? trim((string) file_get_contents($filePath)) : '';
            }
            return $value;
        }
        if (is_array($value)) {
            $resolved = [];
            foreach ($value as $key => $inner) {
                $resolved[$key] = self::resolve($inner, $profileEnv);
            }
            return $resolved;
        }
        return $value;
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,string>
     */
    private static function loadProfileEnv(array $payload): array
    {
        $profile = $payload['config_profile'] ?? null;
        if (!is_array($profile)) {
            return [];
        }
        $file = $profile['file'] ?? null;
        if (!is_string($file) || !is_file($file)) {
            return [];
        }
        $targetEnv = $profile['environment'] ?? null;
        $targetName = $profile['name'] ?? null;

        $autoload = dirname(__DIR__, 2) . '/../blackcat-config/src/autoload.php';
        if (is_file($autoload)) {
            require_once $autoload;
        }

        if (class_exists('\\BlackCat\\Config\\Config\\ProfileConfig')) {
            $profiles = \BlackCat\Config\Config\ProfileConfig::fromFile($file)->profiles();
            foreach ($profiles as $configProfile) {
                $match = ($targetName && $configProfile->name() === $targetName)
                    || ($targetEnv && $configProfile->environment() === $targetEnv);
                if ($match) {
                    return $configProfile->env();
                }
            }
        }

        $raw = require $file;
        if (!is_array($raw)) {
            return [];
        }
        foreach ($raw as $candidate) {
            $match = ($targetName && ($candidate['name'] ?? null) === $targetName)
                || ($targetEnv && ($candidate['environment'] ?? null) === $targetEnv);
            if ($match) {
                $env = $candidate['env'] ?? [];
                return is_array($env) ? array_map('strval', $env) : [];
            }
        }
        return [];
    }

    /**
     * @return array<string,string>
     */
    private function buildEnvPayload(): array
    {
        $auth = $this->payload['auth'] ?? [];
        if (!is_array($auth)) {
            $auth = [];
        }
        $env = [];
        $map = [
            'issuer' => 'BLACKCAT_AUTH_ISSUER',
            'audience' => 'BLACKCAT_AUTH_AUDIENCE',
            'signing_key' => 'BLACKCAT_AUTH_KEY',
            'access_ttl' => 'BLACKCAT_AUTH_ACCESS_TTL',
            'refresh_ttl' => 'BLACKCAT_AUTH_REFRESH_TTL',
            'pkce_window' => 'BLACKCAT_AUTH_PKCE_TTL',
            'public_base_url' => 'BLACKCAT_AUTH_BASE_URL',
        ];
        foreach ($map as $key => $envKey) {
            if (array_key_exists($key, $auth)) {
                $env[$envKey] = (string) $auth[$key];
            }
        }

        $session = $auth['session']['ttl'] ?? null;
        if ($session !== null) {
            $env['BLACKCAT_AUTH_SESSION_TTL'] = (string) $session;
        }
        $sessionStore = $auth['session']['store'] ?? null;
        if (is_array($sessionStore) && $sessionStore !== []) {
            $env['BLACKCAT_AUTH_SESSION_STORE'] = json_encode($sessionStore, JSON_UNESCAPED_SLASHES);
        }

        $magic = $auth['magic_link'] ?? [];
        if (isset($magic['ttl'])) {
            $env['BLACKCAT_AUTH_MAGICLINK_TTL'] = (string) $magic['ttl'];
        }
        if (isset($magic['url'])) {
            $env['BLACKCAT_AUTH_MAGICLINK_URL'] = (string) $magic['url'];
        }

        if (isset($auth['webauthn']['rp_id'])) {
            $env['BLACKCAT_AUTH_WEBAUTHN_RP_ID'] = (string) $auth['webauthn']['rp_id'];
        }
        if (isset($auth['webauthn']['rp_name'])) {
            $env['BLACKCAT_AUTH_WEBAUTHN_RP_NAME'] = (string) $auth['webauthn']['rp_name'];
        }

        if (isset($auth['roles'])) {
            $env['BLACKCAT_AUTH_ROLES'] = json_encode($auth['roles'], JSON_UNESCAPED_SLASHES);
        }
        if (isset($auth['clients'])) {
            $env['BLACKCAT_AUTH_CLIENTS'] = json_encode($auth['clients'], JSON_UNESCAPED_SLASHES);
        }

        if (isset($auth['events']['buffer_size'])) {
            $env['BLACKCAT_AUTH_EVENTS_BUFFER'] = (string) $auth['events']['buffer_size'];
        }
        if (isset($auth['events']['webhooks'])) {
            $env['BLACKCAT_AUTH_EVENT_WEBHOOKS'] = json_encode($auth['events']['webhooks'], JSON_UNESCAPED_SLASHES);
        }

        return $env;
    }
}
