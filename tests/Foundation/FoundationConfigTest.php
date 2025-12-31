<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Foundation;

use BlackCat\Auth\Config\FoundationConfig;
use PHPUnit\Framework\TestCase;

final class FoundationConfigTest extends TestCase
{
    public function testResolvesPlaceholdersAndBuildsAuthConfig(): void
    {
        $tempDir = sys_get_temp_dir() . '/auth-foundation-' . bin2hex(random_bytes(4));
        mkdir($tempDir, 0777, true);
        $configPath = $tempDir . '/config.php';
        $signing = base64_encode(random_bytes(32));
        $_ENV['BLACKCAT_AUTH_SIGNING_KEY'] = $signing;
        putenv('BLACKCAT_AUTH_SIGNING_KEY=' . $signing);
        file_put_contents($configPath, '<?php return ' . var_export([
            'auth' => [
                'issuer' => 'https://auth.test',
                'audience' => 'clients',
                'signing_key' => '${env:BLACKCAT_AUTH_SIGNING_KEY}',
                'access_ttl' => 600,
                'refresh_ttl' => 7200,
                'public_base_url' => 'https://auth.test',
                'pkce_window' => 120,
                'session' => ['ttl' => 1800],
                'magic_link' => [
                    'ttl' => 600,
                    'url' => 'https://auth.test/magic',
                    'dev_return_token' => 1,
                    'throttle' => [
                        'window_sec' => 300,
                        'max_per_ip' => 123,
                        'max_per_email' => 4,
                    ],
                ],
                'webauthn' => [
                    'rp_id' => 'auth.test',
                    'rp_name' => 'BlackCat Auth',
                    'challenge_ttl' => 321,
                ],
                'registration' => [
                    'verify_email_resend_throttle' => [
                        'window_sec' => 222,
                        'max_per_ip' => 33,
                        'max_per_email' => 4,
                    ],
                ],
                'password_reset' => [
                    'throttle' => [
                        'window_sec' => 111,
                        'max_per_ip' => 22,
                        'max_per_email' => 2,
                    ],
                ],
                'events' => ['buffer_size' => 100, 'webhooks' => ['https://webhook.local']],
                'roles' => ['admin' => ['permissions' => ['*']]],
                'clients' => ['svc' => ['secret' => 's', 'roles' => ['svc']]],
            ],
            'user_store' => ['driver' => 'array'],
            'telemetry' => ['prometheus_file' => $tempDir . '/metrics.prom'],
        ], true) . ';');

        $config = FoundationConfig::fromFile($configPath);
        $auth = $config->authConfig();
        self::assertSame('https://auth.test', $auth->issuer());
        self::assertSame(600, $auth->accessTtl());
        self::assertSame(1800, $auth->sessionTtl());
        self::assertSame('https://auth.test/magic', $auth->magicLinkUrl());
        self::assertTrue($auth->devReturnMagicLinkToken());
        self::assertSame(300, $auth->magicLinkThrottleWindowSec());
        self::assertSame(123, $auth->magicLinkThrottleMaxPerIp());
        self::assertSame(4, $auth->magicLinkThrottleMaxPerEmail());
        self::assertSame('auth.test', $auth->webauthnRpId());
        self::assertSame('BlackCat Auth', $auth->webauthnRpName());
        self::assertSame(321, $auth->webauthnChallengeTtlSec());
        self::assertSame(111, $auth->passwordResetThrottleWindowSec());
        self::assertSame(22, $auth->passwordResetThrottleMaxPerIp());
        self::assertSame(2, $auth->passwordResetThrottleMaxPerEmail());
        self::assertSame(222, $auth->verifyEmailResendThrottleWindowSec());
        self::assertSame(33, $auth->verifyEmailResendThrottleMaxPerIp());
        self::assertSame(4, $auth->verifyEmailResendThrottleMaxPerEmail());
        self::assertSame(100, $auth->eventsBufferSize());
        self::assertSame($tempDir . '/metrics.prom', $config->telemetryFile());
    }
}
