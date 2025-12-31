<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Session;

use BlackCat\Sessions\SessionService;
use BlackCat\Sessions\Store\InMemorySessionStore;
use PHPUnit\Framework\TestCase;

final class SessionServiceTest extends TestCase
{
    public function testIssueAndValidate(): void
    {
        $service = new SessionService(new InMemorySessionStore(), 60);
        $session = $service->issue(['sub' => 'user-1'], ['ip' => '127.0.0.1']);
        self::assertNotEmpty($session->id);
        $fetched = $service->validate($session->id);
        self::assertNotNull($fetched);
        self::assertSame('user-1', $fetched->subject);
    }
}
