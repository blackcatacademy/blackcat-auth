<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Session;

use BlackCat\Sessions\Store\SessionStoreFactory;
use PHPUnit\Framework\TestCase;

final class SessionStoreFactoryTest extends TestCase
{
    public function testPdoStoreIsRemoved(): void
    {
        $this->expectException(\RuntimeException::class);
        SessionStoreFactory::fromConfig(['type' => 'pdo']);
    }

    public function testDatabaseStoreRequiresDb(): void
    {
        $this->expectException(\RuntimeException::class);
        SessionStoreFactory::fromConfig(['type' => 'database']);
    }
}
