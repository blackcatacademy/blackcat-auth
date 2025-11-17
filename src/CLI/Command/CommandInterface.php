<?php
declare(strict_types=1);

namespace BlackCat\Auth\CLI\Command;

interface CommandInterface
{
    public function name(): string;
    public function description(): string;
    public function run(array $args, \BlackCat\Auth\Foundation\AuthRuntime $runtime): int;
}
