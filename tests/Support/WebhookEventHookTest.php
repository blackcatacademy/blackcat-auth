<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Support;

use BlackCat\Auth\Support\WebhookEventHook;
use PHPUnit\Framework\TestCase;

final class WebhookEventHookTest extends TestCase
{
    public function testDispatchesToSender(): void
    {
        $calls = [];
        $hook = new WebhookEventHook(['https://example.com/hook'], function (string $url, array $payload) use (&$calls): void {
            $calls[] = ['url' => $url, 'payload' => $payload];
        });
        $hook->onSuccess('password_grant', ['username' => 'demo']);
        self::assertCount(1, $calls);
        self::assertSame('https://example.com/hook', $calls[0]['url']);
        self::assertSame('password_grant', $calls[0]['payload']['event'] ?? null);
    }
}
