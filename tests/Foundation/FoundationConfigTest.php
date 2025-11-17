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
                'magic_link' => ['ttl' => 600, 'url' => 'https://auth.test/magic'],
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
        self::assertSame(100, $auth->eventsBufferSize());
        self::assertSame($tempDir . '/metrics.prom', $config->telemetryFile());
    }
}
