<?php
declare(strict_types=1);

namespace BlackCat\Auth\Foundation;

use BlackCat\Auth\AuthManager;
use BlackCat\Auth\Config\AuthConfig;
use BlackCat\Auth\Config\FoundationConfig;
use BlackCat\Auth\Support\CompositeAuthHook;
use BlackCat\Auth\Support\TelemetryAuthHook;
use BlackCat\Auth\Telemetry\AuthTelemetry;
use InvalidArgumentException;
use PDO;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class AuthRuntime
{
    private AuthManager $auth;
    private LoggerInterface $logger;
    private AuthTelemetry $telemetry;

    private function __construct(
        private readonly FoundationConfig $config,
        private readonly UserStoreInstance $store,
        ?LoggerInterface $logger = null
    ) {
        $this->logger = $logger ?? new NullLogger();
        $this->telemetry = new AuthTelemetry($config->telemetryFile());
        $this->auth = AuthManager::boot(
            $config->authConfig(),
            $store->provider(),
            $this->logger,
            null,
            new CompositeAuthHook(new TelemetryAuthHook($this->telemetry))
        );
    }

    public static function fromFile(string $path, ?LoggerInterface $logger = null): self
    {
        $config = FoundationConfig::fromFile($path);
        $store = UserStoreFactory::create($config->userStore());
        return new self($config, $store, $logger);
    }

    public function config(): FoundationConfig
    {
        return $this->config;
    }

    public function authConfig(): AuthConfig
    {
        return $this->config->authConfig();
    }

    public function auth(): AuthManager
    {
        return $this->auth;
    }

    public function userStore(): UserStoreInstance
    {
        return $this->store;
    }

    public function telemetry(): AuthTelemetry
    {
        return $this->telemetry;
    }

    public function ensureUserStoreSchema(): void
    {
        $pdo = $this->store->pdo();
        if ($pdo === null) {
            return;
        }
        $options = $this->config->userStore();
        $table = $this->identifier($options['table'] ?? 'users');
        $rolesColumn = $this->identifier($options['roles_column'] ?? 'roles');
        $statusColumn = $this->identifier($options['status_column'] ?? 'status');
        $createdColumn = $this->identifier($options['created_at_column'] ?? 'created_at');
        $updatedColumn = $this->identifier($options['updated_at_column'] ?? 'updated_at');
        $sql = sprintf(
            'CREATE TABLE IF NOT EXISTS %s (
                id VARCHAR(190) PRIMARY KEY,
                email VARCHAR(190) NOT NULL UNIQUE,
                password TEXT NOT NULL,
                %s TEXT,
                %s VARCHAR(32) NOT NULL DEFAULT \'active\',
                %s TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                %s TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )',
            $table,
            $rolesColumn,
            $statusColumn,
            $createdColumn,
            $updatedColumn
        );
        $pdo->exec($sql);
    }

    /**
     * @return list<string>
     */
    public function seedUsers(bool $force = false): array
    {
        $pdo = $this->store->pdo();
        $hasher = $this->store->hasher();
        if ($pdo === null || $hasher === null) {
            return [];
        }
        $this->ensureUserStoreSchema();
        $options = $this->config->userStore();
        $table = $this->identifier($options['table'] ?? 'users');
        $emailColumn = $this->identifier($options['email_column'] ?? 'email');
        $passwordColumn = $this->identifier($options['password_column'] ?? 'password');
        $rolesColumn = $this->identifier($options['roles_column'] ?? 'roles');
        $statusColumn = $this->identifier($options['status_column'] ?? 'status');
        $activeValue = (string)($options['status_active_value'] ?? 'active');

        $inserted = [];
        foreach ($this->config->seedUsers() as $user) {
            $email = strtolower((string)($user['email'] ?? ''));
            if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                continue;
            }
            $existing = $this->findUserByEmail($pdo, $table, $emailColumn, $email);
            if ($existing && !$force) {
                continue;
            }
            $id = (string)($user['id'] ?? bin2hex(random_bytes(8)));
            $password = (string)($user['password'] ?? 'secret');
            $roles = json_encode(array_values((array)($user['roles'] ?? [])), JSON_UNESCAPED_SLASHES);
            $hash = $hasher->hash($password);
            if ($existing) {
                $sql = sprintf('UPDATE %s SET %s = :password, %s = :roles, %s = :status WHERE %s = :email', $table, $passwordColumn, $rolesColumn, $statusColumn, $emailColumn);
                $stmt = $pdo->prepare($sql);
                $stmt->execute([
                    ':password' => $hash,
                    ':roles' => $roles,
                    ':status' => $user['status'] ?? $activeValue,
                    ':email' => $email,
                ]);
                $inserted[] = $existing['id'] ?? $id;
                continue;
            }
            $sql = sprintf('INSERT INTO %s (id, %s, %s, %s, %s, created_at, updated_at) VALUES (:id, :email, :password, :roles, :status, :created, :updated)', $table, $emailColumn, $passwordColumn, $rolesColumn, $statusColumn);
            $stmt = $pdo->prepare($sql);
            $stmt->execute([
                ':id' => $id,
                ':email' => $email,
                ':password' => $hash,
                ':roles' => $roles,
                ':status' => $user['status'] ?? $activeValue,
                ':created' => gmdate('Y-m-d H:i:s'),
                ':updated' => gmdate('Y-m-d H:i:s'),
            ]);
            $inserted[] = $id;
        }
        return $inserted;
    }

    /**
     * @return list<array<string,mixed>>
     */
    public function listUsers(int $limit = 20): array
    {
        $pdo = $this->store->pdo();
        if ($pdo === null) {
            return $this->config->seedUsers();
        }
        $options = $this->config->userStore();
        $table = $this->identifier($options['table'] ?? 'users');
        $idColumn = $this->identifier($options['id_column'] ?? 'id');
        $emailColumn = $this->identifier($options['email_column'] ?? 'email');
        $rolesColumn = $this->identifier($options['roles_column'] ?? 'roles');
        $statusColumn = $this->identifier($options['status_column'] ?? 'status');
        $createdColumn = $this->identifier($options['created_at_column'] ?? 'created_at');
        $sql = sprintf('SELECT %s AS id, %s AS email, %s AS roles, %s AS status, %s AS created FROM %s ORDER BY %s DESC LIMIT :limit', $idColumn, $emailColumn, $rolesColumn, $statusColumn, $createdColumn, $table, $createdColumn);
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':limit', max(1, $limit), PDO::PARAM_INT);
        $stmt->execute();
        $rows = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $roles = $row['roles'] ?? '[]';
            $decoded = json_decode((string) $roles, true);
            if (!is_array($decoded)) {
                $decoded = [];
            }
            $rows[] = [
                'id' => $row['id'],
                'email' => $row['email'],
                'roles' => array_values(array_filter($decoded, 'is_string')),
                'status' => $row['status'],
                'created_at' => $row['created'],
            ];
        }
        return $rows;
    }

    /**
     * @return array<string,mixed>
     */
    public function healthReport(): array
    {
        $pdo = $this->store->pdo();
        $report = [
            'config' => $this->config->path(),
            'signing_key_length' => strlen($this->authConfig()->signingKey()),
            'telemetry' => $this->config->telemetryFile() ? 'configured' : 'disabled',
            'user_store_driver' => $pdo ? 'database' : 'array',
        ];
        if ($pdo) {
            $report['database'] = $this->ping($pdo);
        }
        return $report;
    }

    private function findUserByEmail(PDO $pdo, string $table, string $emailColumn, string $email): ?array
    {
        $sql = sprintf('SELECT * FROM %s WHERE %s = :email LIMIT 1', $table, $emailColumn);
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':email', $email);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    private function identifier(string $value): string
    {
        if (!preg_match('/^[A-Za-z0-9_]+$/', $value)) {
            throw new InvalidArgumentException("Unsafe identifier: {$value}");
        }
        return $value;
    }

    private function ping(PDO $pdo): string
    {
        try {
            $pdo->query('SELECT 1');
            return 'ok';
        } catch (\Throwable $e) {
            return 'error: ' . $e->getMessage();
        }
    }
}
