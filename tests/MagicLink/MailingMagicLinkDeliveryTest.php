<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\MagicLink;

use BlackCat\Auth\MagicLink\MailingMagicLinkDelivery;
use BlackCat\Mailing\Queue\EmailQueueInterface;
use PHPUnit\Framework\TestCase;

final class MailingMagicLinkDeliveryTest extends TestCase
{
    public function testQueuesMagicLinkEmail(): void
    {
        $queue = new class implements EmailQueueInterface {
            /** @var list<array{template:string,payload:array<string,mixed>,userId:?int,priority:int,maxRetries:int}> */
            public array $calls = [];

            public function enqueueEmail(
                string $template,
                array $payload,
                ?int $userId = null,
                int $priority = 0,
                int $maxRetries = 6,
            ): int {
                $this->calls[] = [
                    'template' => $template,
                    'payload' => $payload,
                    'userId' => $userId,
                    'priority' => $priority,
                    'maxRetries' => $maxRetries,
                ];
                return 123;
            }
        };

        $delivery = new MailingMagicLinkDelivery($queue, 'magic_link', 10, 'BlackCat Auth');
        $delivery->queueMagicLinkEmail(
            'user@example.com',
            42,
            'token-value',
            'https://app.example.com/magic-login?token=token-value',
            600,
        );

        self::assertCount(1, $queue->calls);
        self::assertSame('magic_link', $queue->calls[0]['template']);
        self::assertSame(42, $queue->calls[0]['userId']);
        self::assertSame(10, $queue->calls[0]['priority']);
        self::assertSame('user@example.com', $queue->calls[0]['payload']['to_email']);
        self::assertSame('https://app.example.com/magic-login?token=token-value', $queue->calls[0]['payload']['vars']['magic_link_url']);
        self::assertSame('BlackCat Auth', $queue->calls[0]['payload']['vars']['app_name']);
        self::assertSame('token-value', $queue->calls[0]['payload']['vars']['token']);
    }
}
