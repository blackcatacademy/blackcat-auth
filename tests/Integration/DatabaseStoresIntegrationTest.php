<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Integration;

use BlackCat\Auth\DeviceCode\DatabaseDeviceCodeStore;
use BlackCat\Auth\DeviceCode\DeviceCodeService;
use BlackCat\Auth\MagicLink\DatabaseMagicLinkStore;
use BlackCat\Auth\MagicLink\MagicLinkService;
use BlackCat\Auth\WebAuthn\DatabaseWebAuthnStore;
use BlackCat\Auth\WebAuthn\WebAuthnService;
use BlackCat\Core\Database;
use BlackCat\Database\Packages\DeviceCodes\DeviceCodesModule;
use BlackCat\Database\Packages\MagicLinks\MagicLinksModule;
use BlackCat\Database\Packages\Users\UsersModule;
use BlackCat\Database\Packages\WebauthnChallenges\Repository\WebauthnChallengeRepository;
use BlackCat\Database\Packages\WebauthnChallenges\WebauthnChallengesModule;
use BlackCat\Database\Packages\WebauthnCredentials\Repository\WebauthnCredentialRepository;
use BlackCat\Database\Packages\WebauthnCredentials\WebauthnCredentialsModule;
use PHPUnit\Framework\TestCase;

/**
 * Requires a real DB (MySQL/Postgres); skipped unless DB_DSN is provided.
 */
final class DatabaseStoresIntegrationTest extends TestCase
{
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    #[\PHPUnit\Framework\Attributes\PreserveGlobalState(false)]
    public function testStage3DbStoresEndToEnd(): void
    {
        $db = $this->initDbOrSkip();
        $dialect = $db->dialect();

        // Postgres views use digest(...) => requires pgcrypto extension.
        if (method_exists($dialect, 'isPg') && $dialect->isPg()) {
            $db->exec('CREATE EXTENSION IF NOT EXISTS pgcrypto;');
        }

        // Install schema packages required by Stage 3 DB stores.
        (new UsersModule())->install($db, $dialect);
        (new DeviceCodesModule())->install($db, $dialect);
        (new MagicLinksModule())->install($db, $dialect);
        (new WebauthnCredentialsModule())->install($db, $dialect);
        (new WebauthnChallengesModule())->install($db, $dialect);

        $this->wipeTables($db, [
            'webauthn_challenges',
            'webauthn_credentials',
            'magic_links',
            'device_codes',
            'users',
        ]);

        // --- Device codes ---
        $deviceStore = new DatabaseDeviceCodeStore($db);
        $deviceService = new DeviceCodeService($deviceStore, 'https://auth.example.com/device/activate', 60, 1);

        $issued = $deviceService->issue('client-1', ['openid']);
        self::assertNotSame('', (string)($issued['device_code'] ?? ''));
        self::assertNotSame('', (string)($issued['user_code'] ?? ''));

        $pending = $deviceService->poll((string)$issued['device_code']);
        self::assertSame('pending', $pending['status']);

        $approved = $deviceService->approve((string)$issued['user_code'], ['access_token' => 'a', 'refresh_token' => 'r']);
        self::assertSame('approved', $approved['status']);

        $pollOk = $deviceService->poll((string)$issued['device_code']);
        self::assertSame('approved', $pollOk['status']);
        self::assertSame('a', (string)($pollOk['tokens']['access_token'] ?? ''));

        // --- Magic links ---
        $magicStore = new DatabaseMagicLinkStore($db);
        $magic = new MagicLinkService($magicStore, 60, 'https://app.example.com/magic', 'test-secret');

        $issuedLink = $magic->issue('sub-1', ['redirect' => '/dashboard']);
        $token = (string)($issuedLink['token'] ?? '');
        self::assertNotSame('', $token);

        $consumed = $magic->consume($token);
        self::assertIsArray($consumed);
        self::assertSame('sub-1', $consumed['subject'] ?? null);
        self::assertSame('/dashboard', $consumed['context']['redirect'] ?? null);

        // Token is one-time.
        self::assertNull($magic->consume($token));

        // --- WebAuthn ---
        $rpId = 'auth.example.com';
        $webauthnStore = new DatabaseWebAuthnStore($db, $rpId, new WebauthnCredentialRepository($db), new WebauthnChallengeRepository($db), 60);
        $webauthn = new WebAuthnService($webauthnStore, $rpId, 'BlackCat Auth');

        // Create an expired challenge row to exercise cleanup.
        $chRepo = new WebauthnChallengeRepository($db);
        $chRepo->upsert([
            'rp_id' => $rpId,
            'challenge_hash' => 'expired-challenge',
            'metadata' => '{"type":"authenticate","subject":"sub-1","allowed":["cred-1"]}',
            'expires_at' => $this->sqlDateTime(time() - 3600),
        ]);

        $startReg = $webauthn->startRegistration('sub-1');
        self::assertNotSame('', (string)($startReg['challenge'] ?? ''));
        self::assertTrue($webauthn->finishRegistration('sub-1', (string)$startReg['challenge'], 'cred-1', 'pk-placeholder'));

        // Expired challenges should be removed by cleanup.
        self::assertNull($chRepo->getByRpIdAndChallengeHash($rpId, 'expired-challenge', false));

        $startAuth = $webauthn->startAuthentication('sub-1');
        self::assertIsArray($startAuth);
        $authChallenge = (string)($startAuth['challenge'] ?? '');
        self::assertNotSame('', $authChallenge);

        // First auth should store sign_count.
        self::assertTrue($webauthn->finishAuthentication('sub-1', $authChallenge, 'cred-1', 1));

        // Replay / non-increasing sign_count should fail (prod hardening).
        $startAuth2 = $webauthn->startAuthentication('sub-1');
        self::assertIsArray($startAuth2);
        self::assertFalse($webauthn->finishAuthentication('sub-1', (string)$startAuth2['challenge'], 'cred-1', 1));
    }

    private function initDbOrSkip(): Database
    {
        $dsn = (string)(getenv('DB_DSN') ?: '');
        if ($dsn === '') {
            self::markTestSkipped('Set DB_DSN to run integration tests (e.g., mysql:... or pgsql:...).');
        }

        Database::init([
            'dsn' => $dsn,
            'user' => getenv('DB_USER') ?: null,
            'pass' => getenv('DB_PASSWORD') ?: null,
        ]);

        return Database::getInstance();
    }

    /**
     * @param list<string> $tables
     */
    private function wipeTables(Database $db, array $tables): void
    {
        foreach ($tables as $table) {
            $table = trim($table);
            if ($table === '') {
                continue;
            }
            try {
                $db->exec('DELETE FROM ' . $table);
            } catch (\Throwable) {
            }
        }
    }

    private function sqlDateTime(int $epochSec): string
    {
        $epochSec = max(0, $epochSec);
        $dt = (new \DateTimeImmutable('@' . $epochSec))->setTimezone(new \DateTimeZone('UTC'));
        return $dt->format('Y-m-d H:i:s.u');
    }
}
