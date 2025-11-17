<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Support;

use BlackCat\Auth\Support\EventBuffer;
use PHPUnit\Framework\TestCase;

final class EventBufferTest extends TestCase
{
    public function testStoresAndSlices(): void
    {
        $buffer = new EventBuffer(3);
        $buffer->push('event.a', ['foo' => 'bar']);
        $buffer->push('event.b', []);
        $events = $buffer->history();
        self::assertCount(2, $events);
        $after = $buffer->history($events[0]['id']);
        self::assertCount(1, $after);
    }
}
