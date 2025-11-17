<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\DeviceCode;

use BlackCat\Auth\DeviceCode\DeviceCodeService;
use BlackCat\Auth\DeviceCode\InMemoryDeviceCodeStore;
use PHPUnit\Framework\TestCase;

final class DeviceCodeServiceTest extends TestCase
{
    public function testIssueApprovePoll(): void
    {
        $service = new DeviceCodeService(new InMemoryDeviceCodeStore(), 'https://auth.example.com/device/activate');
        $issue = $service->issue('client', ['openid']);
        self::assertArrayHasKey('device_code', $issue);
        $pending = $service->poll($issue['device_code']);
        self::assertSame('pending', $pending['status']);
        $service->approve($issue['user_code'], ['access_token' => 'abc', 'refresh_token' => 'def', 'expires_at' => time() + 3600]);
        $result = $service->poll($issue['device_code']);
        self::assertSame('approved', $result['status']);
        self::assertSame('abc', $result['tokens']['access_token']);
    }
}
