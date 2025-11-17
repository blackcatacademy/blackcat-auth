<?php
declare(strict_types=1);

namespace BlackCat\Auth\Token;

use BlackCat\Auth\Config\AuthConfig;
use Psr\Log\LoggerInterface;

final class TokenService
{
    public function __construct(private readonly AuthConfig $config, private readonly LoggerInterface $logger) {}

    public function issue(array $identity, array $claims, array $options = []): TokenPair
    {
        $subject = (string)($identity['id'] ?? $claims['sub'] ?? '');
        if ($subject === '') {
            throw new \RuntimeException('missing_subject');
        }
        $mergedClaims = array_merge(['sub' => $subject], $claims);
        return $this->issueForSubject($subject, $mergedClaims, $options);
    }

    public function issueForSubject(string $subject, array $claims, array $options = []): TokenPair
    {
        $now = time();
        $accessTtl = isset($options['access_ttl']) ? (int)$options['access_ttl'] : $this->config->accessTtl();
        $refreshTtl = isset($options['refresh_ttl']) ? (int)$options['refresh_ttl'] : $this->config->refreshTtl();
        $issueRefresh = $options['refresh'] ?? true;
        $payload = array_merge($claims, [
            'iss' => $this->config->issuer(),
            'aud' => $this->config->audience(),
            'iat' => $now,
            'exp' => $now + $accessTtl,
            'sub' => $subject,
            'type' => 'access',
        ]);
        $access = $this->encode($payload);
        $refresh = '';
        if ($issueRefresh) {
            $refreshPayload = [
                'iss' => $this->config->issuer(),
                'sub' => $subject,
                'type' => 'refresh',
                'iat' => $now,
                'exp' => $now + max($refreshTtl, $accessTtl),
            ];
            $refresh = $this->encode($refreshPayload);
        }
        return new TokenPair($access, $refresh, $payload['exp']);
    }

    public function verify(string $token): array
    {
        $claims = $this->decode($token);
        if (($claims['type'] ?? '') !== 'access') {
            throw new \RuntimeException('invalid_token_type');
        }
        return $claims;
    }

    public function verifyRefresh(string $token): array
    {
        $claims = $this->decode($token);
        if (($claims['type'] ?? '') !== 'refresh') {
            throw new \RuntimeException('invalid_refresh_token');
        }
        return $claims;
    }

    private function encode(array $payload): string
    {
        $header = $this->b64(json_encode(['alg' => 'HS512', 'typ' => 'JWT']));
        $body = $this->b64(json_encode($payload));
        $sig = $this->b64(hash_hmac('sha512', $header . '.' . $body, $this->config->signingKey(), true));
        return $header . '.' . $body . '.' . $sig;
    }

    private function decode(string $token): array
    {
        [$h, $b, $s] = array_pad(explode('.', $token), 3, null);
        if (!$h || !$b || !$s) {
            throw new \RuntimeException('invalid_token');
        }
        $expected = $this->b64(hash_hmac('sha512', $h . '.' . $b, $this->config->signingKey(), true));
        if (!hash_equals($expected, $s)) {
            throw new \RuntimeException('invalid_signature');
        }
        $claims = json_decode($this->b64decode($b), true) ?: [];
        if (($claims['exp'] ?? 0) < time()) {
            throw new \RuntimeException('token_expired');
        }
        return $claims;
    }

    private function b64(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function b64decode(string $data): string
    {
        $data .= str_repeat('=', (4 - strlen($data) % 4) % 4);
        return base64_decode(strtr($data, '-_', '+/')) ?: '';
    }
}
