<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Http;

use BlackCat\Auth\Config\AuthConfig;
use BlackCat\Auth\Http\HttpServer;
use BlackCat\Auth\Identity\ArrayUserProvider;
use PHPUnit\Framework\TestCase;

final class HttpServerTest extends TestCase
{
    public function testRegistrationEndpointsAreDisabledByDefault(): void
    {
        $config = new AuthConfig(
            'https://auth.example.com',
            'aud',
            base64_encode(random_bytes(32)),
            900,
            3600,
            [],
            [],
            300,
            'https://auth.example.com',
            null
        );
        $provider = new ArrayUserProvider([
            ['id' => 'demo', 'email' => 'demo@example.com', 'password' => 'secret', 'roles' => ['admin']],
        ]);
        $server = HttpServer::bootstrap($config, $provider);

        $register = $server->handle([
            'method' => 'POST',
            'path' => '/register',
            'body' => ['email' => 'demo@example.com', 'password' => 'secret'],
            'headers' => [],
        ]);
        self::assertSame(501, $register['status']);

        $verify = $server->handle([
            'method' => 'POST',
            'path' => '/verify-email',
            'body' => ['token' => 'x.y'],
            'headers' => [],
        ]);
        self::assertSame(501, $verify['status']);

        $resetRequest = $server->handle([
            'method' => 'POST',
            'path' => '/password-reset/request',
            'body' => ['email' => 'demo@example.com'],
            'headers' => [],
        ]);
        self::assertSame(501, $resetRequest['status']);

        $resetConfirm = $server->handle([
            'method' => 'POST',
            'path' => '/password-reset/confirm',
            'body' => ['token' => 'x.y', 'new_password' => 'secret'],
            'headers' => [],
        ]);
        self::assertSame(501, $resetConfirm['status']);
    }

    public function testUserinfoEndpoint(): void
    {
        $config = new AuthConfig(
            'https://auth.example.com',
            'aud',
            base64_encode(random_bytes(32)),
            900,
            3600,
            [],
            ['client' => ['secret' => 'secret', 'roles' => ['svc']]],
            300,
            'https://auth.example.com',
            null
        );
        $provider = new ArrayUserProvider([
            ['id' => 'demo', 'email' => 'demo@example.com', 'password' => 'secret', 'roles' => ['admin']],
        ]);
        $server = HttpServer::bootstrap($config, $provider);
        $login = $server->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['username' => 'demo@example.com', 'password' => 'secret'],
            'headers' => [],
        ]);
        self::assertSame(200, $login['status']);
        $token = $login['body']['access_token'];
        $userinfo = $server->handle([
            'method' => 'GET',
            'path' => '/userinfo',
            'body' => [],
            'headers' => ['Authorization' => 'Bearer ' . $token],
        ]);
        self::assertSame(200, $userinfo['status']);
        self::assertSame('demo', substr($userinfo['body']['sub'], 0, 4));
    }

    public function testSessionLifecycle(): void
    {
        $config = new AuthConfig(
            'https://auth.example.com',
            'aud',
            base64_encode(random_bytes(32)),
            900,
            3600,
            [],
            ['client' => ['secret' => 'secret', 'roles' => ['svc']]],
            300,
            'https://auth.example.com',
            3600
        );
        $provider = new ArrayUserProvider([
            ['id' => 'demo', 'email' => 'demo@example.com', 'password' => 'secret', 'roles' => ['admin']],
        ]);
        $server = HttpServer::bootstrap($config, $provider);
        $login = $server->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['username' => 'demo@example.com', 'password' => 'secret'],
            'headers' => [],
        ]);
        $token = $login['body']['access_token'];
        $issue = $server->handle([
            'method' => 'POST',
            'path' => '/session',
            'body' => ['context' => ['ip' => '127.0.0.1']],
            'headers' => ['Authorization' => 'Bearer ' . $token],
        ]);
        self::assertSame(201, $issue['status']);
        $sessionId = $issue['body']['session_id'];

        $list = $server->handle([
            'method' => 'GET',
            'path' => '/session',
            'body' => [],
            'headers' => ['Authorization' => 'Bearer ' . $token],
        ]);
        self::assertSame(200, $list['status']);
        self::assertNotEmpty($list['body']);

        $delete = $server->handle([
            'method' => 'DELETE',
            'path' => '/session/' . $sessionId,
            'body' => [],
            'headers' => ['Authorization' => 'Bearer ' . $token],
        ]);
        self::assertSame(204, $delete['status']);
    }

    public function testDeviceCodeFlow(): void
    {
        $config = new AuthConfig(
            'https://auth.example.com',
            'aud',
            base64_encode(random_bytes(32)),
            900,
            3600,
            [],
            ['device-client' => ['secret' => 'svc', 'roles' => ['svc']]],
            300,
            'https://auth.example.com',
            null
        );
        $provider = new ArrayUserProvider([
            ['id' => 'demo', 'email' => 'demo@example.com', 'password' => 'secret', 'roles' => ['admin']],
        ]);
        $server = HttpServer::bootstrap($config, $provider);

        $issue = $server->handle([
            'method' => 'POST',
            'path' => '/device/code',
            'body' => ['client_id' => 'device-client', 'scope' => 'openid'],
            'headers' => [],
        ]);
        self::assertSame(200, $issue['status']);
        $deviceCode = $issue['body']['device_code'];
        $userCode = $issue['body']['user_code'];

        $activate = $server->handle([
            'method' => 'POST',
            'path' => '/device/activate',
            'body' => [
                'user_code' => $userCode,
                'username' => 'demo@example.com',
                'password' => 'secret',
            ],
            'headers' => [],
        ]);
        self::assertSame(200, $activate['status']);

        $poll = $server->handle([
            'method' => 'POST',
            'path' => '/device/token',
            'body' => ['device_code' => $deviceCode],
            'headers' => [],
        ]);
        self::assertSame(200, $poll['status']);
        self::assertArrayHasKey('access_token', $poll['body']);
    }

    public function testMagicLinkFlow(): void
    {
        $config = new AuthConfig(
            'https://auth.example.com',
            'aud',
            base64_encode(random_bytes(32)),
            900,
            3600,
            [],
            [],
            300,
            'https://auth.example.com',
            null,
            [],
            600,
            'https://auth.example.com/magic-login',
            devReturnMagicLinkToken: true,
        );
        $provider = new ArrayUserProvider([
            ['id' => 'demo', 'email' => 'demo@example.com', 'password' => 'secret', 'roles' => ['admin']],
        ]);
        $server = HttpServer::bootstrap($config, $provider);
        $request = $server->handle([
            'method' => 'POST',
            'path' => '/magic-link/request',
            'body' => ['email' => 'demo@example.com'],
            'headers' => [],
        ]);
        self::assertSame(200, $request['status']);
        $token = $request['body']['token'];
        $consume = $server->handle([
            'method' => 'POST',
            'path' => '/magic-link/consume',
            'body' => ['token' => $token],
            'headers' => [],
        ]);
        self::assertSame(200, $consume['status']);
        self::assertArrayHasKey('access_token', $consume['body']);
    }

    public function testWebauthnFlow(): void
    {
        $config = new AuthConfig(
            'https://auth.example.com',
            'aud',
            base64_encode(random_bytes(32)),
            900,
            3600,
            [],
            ['device-client' => ['secret' => 'svc', 'roles' => ['svc']]],
            300,
            'https://auth.example.com',
            null,
            [],
            null,
            'https://app.example.com/magic',
            webauthnRpId: 'auth.example.com',
            webauthnRpName: 'BlackCat Auth',
        );
        $provider = new ArrayUserProvider([
            ['id' => 'demo', 'email' => 'demo@example.com', 'password' => 'secret', 'roles' => ['admin']],
        ]);
        $server = HttpServer::bootstrap($config, $provider);
        $login = $server->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['username' => 'demo@example.com', 'password' => 'secret'],
            'headers' => [],
        ]);
        $token = $login['body']['access_token'] ?? '';

        $start = $server->handle([
            'method' => 'POST',
            'path' => '/webauthn/register/start',
            'headers' => ['Authorization' => 'Bearer ' . $token],
            'body' => [],
        ]);
        self::assertSame(200, $start['status']);
        $challenge = $start['body']['challenge'];

        $finish = $server->handle([
            'method' => 'POST',
            'path' => '/webauthn/register/finish',
            'headers' => ['Authorization' => 'Bearer ' . $token],
            'body' => [
                'challenge' => $challenge,
                'credential_id' => 'cred-1',
                'public_key' => 'pk-placeholder',
            ],
        ]);
        self::assertSame(200, $finish['status']);

        $authStart = $server->handle([
            'method' => 'POST',
            'path' => '/webauthn/authenticate/start',
            'body' => ['email' => 'demo@example.com'],
            'headers' => [],
        ]);
        self::assertSame(200, $authStart['status']);
        $authChallenge = $authStart['body']['challenge'];

        $authFinish = $server->handle([
            'method' => 'POST',
            'path' => '/webauthn/authenticate/finish',
            'body' => [
                'email' => 'demo@example.com',
                'challenge' => $authChallenge,
                'credential_id' => 'cred-1',
            ],
            'headers' => [],
        ]);
        self::assertSame(200, $authFinish['status']);
        self::assertArrayHasKey('access_token', $authFinish['body']);
    }

    public function testEventsStream(): void
    {
        $config = new AuthConfig(
            'https://auth.example.com',
            'aud',
            base64_encode(random_bytes(32)),
            900,
            3600,
            [],
            [],
            300,
            'https://auth.example.com'
        );
        $provider = new ArrayUserProvider([
            ['id' => '1', 'email' => 'user@example.com', 'password' => 'secret', 'roles' => ['admin']],
        ]);
        $server = HttpServer::bootstrap($config, $provider);
        $server->handle([
            'method' => 'POST',
            'path' => '/login',
            'body' => ['username' => 'user@example.com', 'password' => 'secret'],
            'headers' => [],
            'query' => [],
        ]);
        $events = $server->handle([
            'method' => 'GET',
            'path' => '/events/stream',
            'body' => [],
            'headers' => [],
            'query' => [],
        ]);
        self::assertSame(200, $events['status']);
        self::assertNotEmpty($events['body']['events']);
    }
}
