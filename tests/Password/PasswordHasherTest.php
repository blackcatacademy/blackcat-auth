<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Password;

use BlackCat\Auth\Password\Pepper;
use BlackCat\Auth\Password\PepperProviderInterface;
use BlackCat\Auth\Password\PasswordHasher;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    public function testHashAndVerify(): void
    {
        $provider = new class implements PepperProviderInterface {
            public function current(): Pepper
            {
                return new Pepper(str_repeat('P', 32), 'test');
            }

            public function all(): array
            {
                return [$this->current()];
            }

            public function byVersion(string $version): ?Pepper
            {
                return $version === 'test' ? $this->current() : null;
            }
        };

        $hasher = new PasswordHasher($provider);
        $hash = $hasher->hash('secret');
        $result = $hasher->verify('secret', $hash, null);
        self::assertTrue($result->isValid());
    }
}
