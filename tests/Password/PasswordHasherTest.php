<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Password;

use BlackCat\Auth\Password\EnvPepperProvider;
use BlackCat\Auth\Password\PasswordHasher;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    protected function setUp(): void
    {
        $_ENV['BLACKCAT_AUTH_PEPPER'] = base64_encode(str_repeat('P', 32));
    }

    public function testHashAndVerify(): void
    {
        $hasher = new PasswordHasher(new EnvPepperProvider());
        $hash = $hasher->hash('secret');
        $result = $hasher->verify('secret', $hash, null);
        self::assertTrue($result->isValid());
    }
}
