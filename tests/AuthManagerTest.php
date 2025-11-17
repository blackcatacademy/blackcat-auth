<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests;

use BlackCat\Auth\AuthManager;
use BlackCat\Auth\Config\AuthConfig;
use BlackCat\Auth\Identity\ArrayUserProvider;
use BlackCat\Auth\Pkce\PkceHelper;
use PHPUnit\Framework\TestCase;

final class AuthManagerTest extends TestCase
{
    public function testIssueTokens(): void
    {
        $config = new AuthConfig(
            'issuer',
            'aud',
            base64_encode(random_bytes(32)),
            900,
            3600,
            ['admin' => ['permissions' => ['admin']]],
            ['service-api' => ['secret' => 'svc', 'roles' => ['svc']]],
            300,
            'https://auth.local',
            null
        );
        $provider = new ArrayUserProvider([
            ['id' => '1', 'email' => 'user@example.com', 'password' => 'secret', 'roles' => ['admin']],
        ]);
        $auth = AuthManager::boot($config, $provider);
        $pair = $auth->issueTokens('user@example.com', 'secret');
        self::assertNotEmpty($pair->accessToken);
        $claims = $auth->verifyAccessToken($pair->accessToken);
        $auth->enforce('admin', $claims);
    }

    public function testClientCredentialsFlow(): void
    {
        $config = new AuthConfig(
            'issuer',
            'aud',
            base64_encode(random_bytes(32)),
            900,
            3600,
            [],
            ['service-api' => ['secret' => 'svc-secret', 'roles' => ['svc'], 'scopes' => ['sync']]],
            180,
            'https://auth.local',
            null
        );
        $auth = AuthManager::boot($config, new ArrayUserProvider([]));
        $tokens = $auth->clientCredentials('service-api', 'svc-secret');
        self::assertNotEmpty($tokens->accessToken);
        $claims = $auth->verifyAccessToken($tokens->accessToken);
        self::assertSame('client:service-api', $claims['sub']);
        self::assertSame(['svc'], $claims['roles']);
    }

    public function testPkceFlow(): void
    {
        $config = new AuthConfig(
            'issuer',
            'aud',
            base64_encode(random_bytes(32)),
            900,
            3600,
            [],
            ['service-api' => ['secret' => 'svc', 'roles' => ['svc']]],
            300,
            'https://auth.local',
            null
        );
        $provider = new ArrayUserProvider([
            ['id' => 'u1', 'email' => 'user@example.com', 'password' => 'secret', 'roles' => ['svc']],
        ]);
        $auth = AuthManager::boot($config, $provider);
        $verifier = bin2hex(random_bytes(16));
        $challenge = PkceHelper::challengeFromVerifier($verifier);
        $code = $auth->initiatePkce('service-api', 'user@example.com', 'secret', $challenge);
        self::assertNotEmpty($code);
        $pair = $auth->exchangePkce('service-api', $code, $verifier);
        self::assertNotEmpty($pair->accessToken);
    }
}
