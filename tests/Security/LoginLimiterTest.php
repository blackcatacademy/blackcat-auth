<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Security;

use BlackCat\Auth\Security\LoginLimiter;
use PHPUnit\Framework\TestCase;

final class LoginLimiterTest extends TestCase
{
    public function testFailOpenWithoutInitializedDatabase(): void
    {
        self::assertFalse(LoginLimiter::isBlocked('127.0.0.1'));
        self::assertSame(0, LoginLimiter::getAttemptsCount('127.0.0.1'));
        self::assertSame(0, LoginLimiter::getSecondsUntilUnblock('127.0.0.1'));

        // Must not throw when DB/ingress is missing.
        LoginLimiter::registerAttempt('127.0.0.1', false, null, 'admin@example.com');
        self::assertTrue(true);
    }
}

