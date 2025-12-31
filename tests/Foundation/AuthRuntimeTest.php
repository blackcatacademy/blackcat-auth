<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Foundation;

use BlackCat\Auth\Foundation\AuthRuntime;
use PHPUnit\Framework\TestCase;

final class AuthRuntimeTest extends TestCase
{
    public function testBootsWithArrayStoreAndWritesTelemetry(): void
    {
        $dir = sys_get_temp_dir() . '/auth-runtime-' . bin2hex(random_bytes(4));
        mkdir($dir, 0777, true);
        $metrics = $dir . '/metrics.prom';
        $configPath = $dir . '/config.php';
        $pepper = base64_encode(random_bytes(32));
        $signingKey = base64_encode(random_bytes(32));
        $_ENV['BLACKCAT_AUTH_SIGNING_KEY'] = $signingKey;
        putenv('BLACKCAT_AUTH_SIGNING_KEY=' . $signingKey);
        $_ENV['BLACKCAT_SERVICE_API_SECRET'] = 'svc-secret';
        putenv('BLACKCAT_SERVICE_API_SECRET=svc-secret');
        $_ENV['BLACKCAT_AUTH_PEPPER'] = $pepper;
        putenv('BLACKCAT_AUTH_PEPPER=' . $pepper);
        file_put_contents($configPath, '<?php return ' . var_export([
            'auth' => [
                'issuer' => 'https://auth.local',
                'audience' => 'clients',
                'signing_key' => '${env:BLACKCAT_AUTH_SIGNING_KEY}',
                'public_base_url' => 'https://auth.local',
                'roles' => ['admin' => ['permissions' => ['*']]],
                'clients' => ['service-api' => ['secret' => '${env:BLACKCAT_SERVICE_API_SECRET}', 'roles' => ['svc']]],
            ],
            'user_store' => [
                'driver' => 'array',
                'pepper_env' => 'BLACKCAT_AUTH_PEPPER',
                'users' => [
                    ['id' => 'demo', 'email' => 'admin@example.com', 'password' => 'secret', 'roles' => ['admin']],
                ],
            ],
            'seed_users' => [
                ['email' => 'admin@example.com', 'password' => 'secret', 'roles' => ['admin']],
            ],
            'telemetry' => ['prometheus_file' => $metrics],
        ], true) . ';');

        $runtime = AuthRuntime::fromFile($configPath);
        $runtime->ensureUserStoreSchema();
        $ids = $runtime->seedUsers(true);
        self::assertSame([], $ids);
        $users = $runtime->listUsers(5);
        self::assertSame('admin@example.com', $users[0]['email']);

        $runtime->auth()->issueTokens('admin@example.com', 'secret');
        $this->assertFileExists($metrics);
        $contents = file_get_contents($metrics);
        self::assertStringContainsString('blackcat_auth_events_password_grant_success_total', (string)$contents);
    }
}
