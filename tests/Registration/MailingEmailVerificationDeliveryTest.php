<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Registration;

use BlackCat\Auth\Registration\MailingEmailVerificationDelivery;
use BlackCat\Mailing\Queue\EmailQueueInterface;
use PHPUnit\Framework\TestCase;

final class MailingEmailVerificationDeliveryTest extends TestCase
{
    public function testQueuesVerificationEmail(): void
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

        $delivery = new MailingEmailVerificationDelivery($queue, 'verify_email', 10, 'BlackCat Auth');
        $delivery->queueVerificationEmail(
            'user@example.com',
            42,
            'sel.val',
            'https://app.example.com/verify?token=sel.val',
            86400,
        );

        self::assertCount(1, $queue->calls);
        self::assertSame('verify_email', $queue->calls[0]['template']);
        self::assertSame(42, $queue->calls[0]['userId']);
        self::assertSame(10, $queue->calls[0]['priority']);
        self::assertSame('user@example.com', $queue->calls[0]['payload']['to_email']);
        self::assertSame('https://app.example.com/verify?token=sel.val', $queue->calls[0]['payload']['vars']['verify_url']);
        self::assertSame('BlackCat Auth', $queue->calls[0]['payload']['vars']['app_name']);
    }
}

