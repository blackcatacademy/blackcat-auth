<?php
declare(strict_types=1);

namespace BlackCat\Auth\Identity;

use BlackCat\Auth\Password\PasswordHasher;
use BlackCat\Auth\Password\PasswordVerificationResult;

final class DatabaseUserProvider implements IdentityProviderInterface
{
    public function __construct(
        private readonly \PDO $pdo,
        private readonly PasswordHasher $hasher,
        private readonly EmailHasherInterface $emailHasher,
        private readonly array $options = []
    ) {}

    public function validateCredentials(string $username, string $password): ?array
    {
        $lookup = $this->lookupByEmail($username);
        $user = $lookup['user'];
        if ($user === null) {
            return null;
        }

        if (!$this->isActive($user)) {
            return null;
        }

        $hashField = $this->options['password_column'] ?? 'password';
        $versionField = $this->options['pepper_version_column'] ?? null;
        $storedHash = (string)($user[$hashField] ?? '');
        $version = $versionField ? ($user[$versionField] ?? null) : null;
        $result = $this->hasher->verify($password, $storedHash, $version ?: null);
        if (!$result->isValid()) {
            return null;
        }
        return $user;
    }

    public function findById(string $id): ?array
    {
        $table = $this->options['table'] ?? 'users';
        $idColumn = $this->options['id_column'] ?? 'id';
        $stmt = $this->pdo->prepare(sprintf('SELECT * FROM %s WHERE %s = :id LIMIT 1', $table, $idColumn));
        $stmt->bindValue(':id', $id);
        $stmt->execute();
        $user = $stmt->fetch(\PDO::FETCH_ASSOC) ?: null;
        return $user && $this->isActive($user) ? $user : null;
    }

    public function claims(array $identity): array
    {
        return [
            'sub' => (string)$identity[$this->options['id_column'] ?? 'id'],
            'email' => $identity[$this->options['email_column'] ?? 'email'] ?? null,
            'roles' => $this->extractRoles($identity),
        ];
    }

    /**
     * Lookup user by email and return metadata similar to legacy Auth::lookupUserByEmail.
     *
     * @return array{user:array|null,usernameHashBinForAttempt:?
string,matched_email_hash_version:?string}
     */
    public function lookupByEmail(string $email): array
    {
        $normalized = $this->emailHasher->normalize($email);
        $results = [
            'user' => null,
            'usernameHashBinForAttempt' => null,
            'matched_email_hash_version' => null,
        ];

        $latest = $this->emailHasher->latest($normalized);
        $results['usernameHashBinForAttempt'] = $latest?->value;

        $table = $this->options['table'] ?? 'users';
        $hashColumn = $this->options['email_hash_column'] ?? null;
        $emailColumn = $this->options['email_column'] ?? 'email';

        if ($hashColumn) {
            $candidates = $this->emailHasher->candidates($normalized);
            if ($candidates) {
                $sql = sprintf('SELECT * FROM %s WHERE %s = :hash LIMIT 1', $table, $hashColumn);
                $stmt = $this->pdo->prepare($sql);
                foreach ($candidates as $candidate) {
                    $stmt->bindValue(':hash', $candidate->value, \PDO::PARAM_LOB);
                    $stmt->execute();
                    $user = $stmt->fetch(\PDO::FETCH_ASSOC) ?: null;
                    if ($user) {
                        $results['user'] = $user;
                        $results['matched_email_hash_version'] = $candidate->version;
                        return $results;
                    }
                }
            }
        }

        $sql = sprintf('SELECT * FROM %s WHERE %s = :email LIMIT 1', $table, $emailColumn);
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindValue(':email', $normalized);
        $stmt->execute();
        $user = $stmt->fetch(\PDO::FETCH_ASSOC) ?: null;
        if ($user) {
            $results['user'] = $user;
        }
        return $results;
    }

    public function findByEmail(string $email): ?array
    {
        $lookup = $this->lookupByEmail($email);
        return $lookup['user'];
    }

    private function extractRoles(array $user): array
    {
        $key = $this->options['roles_column'] ?? 'roles';
        $raw = $user[$key] ?? null;
        if (is_string($raw)) {
            $json = json_decode($raw, true);
            if (is_array($json)) {
                return array_values(array_filter($json, 'is_string'));
            }
            if (str_contains($raw, ',')) {
                return array_map('trim', explode(',', $raw));
            }
            return [$raw];
        }
        if (is_array($raw)) {
            return $raw;
        }
        return [];
    }

    private function isActive(array $user): bool
    {
        $column = $this->options['status_column'] ?? null;
        if ($column === null) {
            return true;
        }
        $activeValue = $this->options['status_active_value'] ?? 1;
        return (string)($user[$column] ?? '') === (string)$activeValue;
    }
}
