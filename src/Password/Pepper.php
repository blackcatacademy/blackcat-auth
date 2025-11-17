<?php
declare(strict_types=1);

namespace BlackCat\Auth\Password;

final class Pepper
{
    public function __construct(
        private string $bytes,
        public readonly string $version,
    ) {}

    public function bytes(): string
    {
        return $this->bytes;
    }

    public function release(): void
    {
        if (function_exists('sodium_memzero')) {
            @sodium_memzero($this->bytes);
        } else {
            $this->bytes = str_repeat("\0", strlen($this->bytes));
        }
    }
}
