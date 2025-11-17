<?php
declare(strict_types=1);

namespace BlackCat\Auth\Foundation;

use BlackCat\Auth\Identity\IdentityProviderInterface;
use BlackCat\Auth\Password\PasswordHasher;

final class UserStoreInstance
{
    public function __construct(
        private readonly IdentityProviderInterface $provider,
        private readonly ?\PDO $pdo,
        private readonly ?PasswordHasher $hasher
    ) {
    }

    public function provider(): IdentityProviderInterface
    {
        return $this->provider;
    }

    public function pdo(): ?\PDO
    {
        return $this->pdo;
    }

    public function hasher(): ?PasswordHasher
    {
        return $this->hasher;
    }
}
