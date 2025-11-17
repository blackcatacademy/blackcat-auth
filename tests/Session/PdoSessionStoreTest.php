<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Session;

use BlackCat\Auth\Session\PdoSessionStore;
use BlackCat\Auth\Session\SessionRecord;
use PHPUnit\Framework\TestCase;

final class PdoSessionStoreTest extends TestCase
{
    public function testSaveAndRetrieve(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $store = new PdoSessionStore($pdo, 'sessions');
        $record = new SessionRecord('sess-1', 'user-1', time(), time() + 600, ['sub' => 'user-1'], ['ip' => '127.0.0.1']);
        $store->save($record);
        $fetched = $store->find('sess-1');
        self::assertNotNull($fetched);
        self::assertSame('user-1', $fetched->subject);
        $all = $store->findBySubject('user-1');
        self::assertCount(1, $all);
        $store->revoke('sess-1');
        self::assertNull($store->find('sess-1'));
    }
}
