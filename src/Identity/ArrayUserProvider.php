<?php
declare(strict_types=1);

namespace BlackCat\Auth\Identity;

final class ArrayUserProvider implements IdentityProviderInterface
{
    /** @var array<int,array<string,mixed>> */
    private array $users;

    public function __construct(array $users)
    {
        $this->users = array_map(function ($user) {
            $user['password'] = password_hash($user['password'] ?? '', PASSWORD_ARGON2ID);
            return $user;
        }, $users);
    }

    public function validateCredentials(string $username, string $password): ?array
    {
        foreach ($this->users as $user) {
            if (($user['email'] ?? $user['username'] ?? null) === $username && password_verify($password, $user['password'])) {
                return $user;
            }
        }
        return null;
    }

    public function findById(string $id): ?array
    {
        foreach ($this->users as $user) {
            if ((string)($user['id'] ?? '') === $id) {
                return $user;
            }
        }
        return null;
    }

    public function claims(array $identity): array
    {
        return [
            'sub' => (string)($identity['id'] ?? ''),
            'email' => $identity['email'] ?? null,
            'roles' => $identity['roles'] ?? [],
        ];
    }

    public function findByEmail(string $email): ?array
    {
        foreach ($this->users as $user) {
            if (strcasecmp((string)($user['email'] ?? ''), $email) === 0) {
                return $user;
            }
        }
        return null;
    }
}
