<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Foundation;

use BlackCat\Auth\Foundation\UserStoreFactory;
use PHPUnit\Framework\TestCase;

final class UserStoreFactoryTest extends TestCase
{
    public function testDatabaseStoreRejectsSqliteDsn(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        UserStoreFactory::create([
            'driver' => 'database',
            'dsn' => 'sqlite::memory:',
        ]);
    }
}

