<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\WebAuthn;

use BlackCat\Auth\WebAuthn\WebAuthnService;
use BlackCat\Auth\WebAuthn\InMemoryWebAuthnStore;
use PHPUnit\Framework\TestCase;

final class WebAuthnServiceTest extends TestCase
{
    public function testRegistrationAndAuthenticationFlow(): void
    {
        $service = new WebAuthnService(new InMemoryWebAuthnStore(), 'auth.example.com', 'BlackCat Auth');
        $start = $service->startRegistration('user-1');
        self::assertArrayHasKey('challenge', $start);
        $finish = $service->finishRegistration('user-1', $start['challenge'], 'cred-1', 'pk');
        self::assertTrue($finish);

        $authStart = $service->startAuthentication('user-1');
        self::assertNotNull($authStart);
        $authFinish = $service->finishAuthentication('user-1', $authStart['challenge'], 'cred-1');
        self::assertTrue($authFinish);
    }
}
