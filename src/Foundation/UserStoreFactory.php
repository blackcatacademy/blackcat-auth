<?php
declare(strict_types=1);

namespace BlackCat\Auth\Foundation;

use BlackCat\Auth\Identity\ArrayUserProvider;
use BlackCat\Auth\Identity\DatabaseUserProvider;
use BlackCat\Auth\Identity\PlainEmailHasher;
use BlackCat\Auth\Password\EnvPepperProvider;
use BlackCat\Auth\Password\PasswordHasher;
use InvalidArgumentException;
use PDO;

final class UserStoreFactory
{
    /**
     * @param array<string,mixed> $config
     */
    public static function create(array $config): UserStoreInstance
    {
        $driver = $config['driver'] ?? 'array';
        if ($driver === 'database') {
            return self::createDatabaseStore($config);
        }

        $users = is_array($config['users'] ?? null) ? $config['users'] : [];
        return new UserStoreInstance(new ArrayUserProvider($users), null, null);
    }

    /**
     * @param array<string,mixed> $config
     */
    private static function createDatabaseStore(array $config): UserStoreInstance
    {
        $dsn = (string)($config['dsn'] ?? '');
        if ($dsn === '') {
            throw new InvalidArgumentException('user_store.dsn is required for database driver.');
        }
        $user = $config['username'] ?? null;
        $password = $config['password'] ?? null;
        self::prepareSqlitePath($dsn);
        $pdo = new PDO($dsn, $user, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
        if (!empty($config['attributes']) && is_array($config['attributes'])) {
            foreach ($config['attributes'] as $attr => $value) {
                if (is_int($attr)) {
                    continue;
                }
                $pdo->setAttribute((int) $attr, $value);
            }
        }
        $pepperEnv = (string)($config['pepper_env'] ?? 'BLACKCAT_AUTH_PEPPER');
        $hasher = new PasswordHasher(new EnvPepperProvider($pepperEnv));
        $provider = new DatabaseUserProvider(
            $pdo,
            $hasher,
            new PlainEmailHasher(),
            [
                'table' => $config['table'] ?? 'users',
                'id_column' => $config['id_column'] ?? 'id',
                'email_column' => $config['email_column'] ?? 'email',
                'password_column' => $config['password_column'] ?? 'password',
                'roles_column' => $config['roles_column'] ?? 'roles',
                'status_column' => $config['status_column'] ?? 'status',
                'status_active_value' => $config['status_active_value'] ?? 'active',
            ]
        );
        return new UserStoreInstance($provider, $pdo, $hasher);
    }

    private static function prepareSqlitePath(string $dsn): void
    {
        if (!str_starts_with($dsn, 'sqlite:')) {
            return;
        }
        $path = substr($dsn, 7);
        if ($path === ':memory:' || $path === '') {
            return;
        }
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
    }
}
