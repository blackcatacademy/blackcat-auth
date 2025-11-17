<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\MagicLink;

use BlackCat\Auth\MagicLink\MagicLinkService;
use BlackCat\Auth\MagicLink\InMemoryMagicLinkStore;
use PHPUnit\Framework\TestCase;

final class MagicLinkServiceTest extends TestCase
{
    public function testIssueAndConsume(): void
    {
        $service = new MagicLinkService(new InMemoryMagicLinkStore(), 300, 'https://auth.example.com/magic-login', 'secret');
        $issued = $service->issue('user-1', ['redirect' => '/dashboard']);
        self::assertArrayHasKey('token', $issued);
        $payload = $service->consume($issued['token']);
        self::assertNotNull($payload);
        self::assertSame('user-1', $payload['subject']);
        self::assertSame('/dashboard', $payload['context']['redirect']);
    }
}
