<?php
declare(strict_types=1);

namespace BlackCat\Auth\DeviceCode;

final class DeviceCodeEntry
{
    public function __construct(
        public readonly string $deviceCode,
        public readonly string $userCode,
        public readonly string $clientId,
        public readonly array $scopes,
        public readonly int $expiresAt,
        public readonly int $interval,
        private readonly ?array $tokenPayload = null,
    ) {}

    public function isExpired(): bool
    {
        return $this->expiresAt <= time();
    }

    public function isApproved(): bool
    {
        return $this->tokenPayload !== null;
    }

    public function tokens(): ?array
    {
        return $this->tokenPayload;
    }

    public function markApproved(array $tokens): self
    {
        return new self(
            $this->deviceCode,
            $this->userCode,
            $this->clientId,
            $this->scopes,
            $this->expiresAt,
            $this->interval,
            $tokens
        );
    }
}
