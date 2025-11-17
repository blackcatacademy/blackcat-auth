<?php
declare(strict_types=1);

namespace BlackCat\Auth\Session;

final class SessionStoreFactory
{
    /**
     * @param array<string,mixed> $config
     */
    public static function fromConfig(array $config): SessionStoreInterface
    {
        $type = strtolower((string)($config['type'] ?? 'memory'));
        return match ($type) {
            'pdo' => self::pdoStore($config),
            'redis' => self::redisStore($config),
            default => new InMemorySessionStore(),
        };
    }

    /**
     * @param array<string,mixed> $config
     */
    private static function pdoStore(array $config): SessionStoreInterface
    {
        $dsn = $config['dsn'] ?? null;
        if (!$dsn) {
            throw new \RuntimeException('Session store (pdo) requires dsn.');
        }
        $options = $config['options'] ?? [];
        $pdo = new \PDO(
            (string)$dsn,
            $config['user'] ?? null,
            $config['pass'] ?? null,
            is_array($options) ? $options : []
        );
        return new PdoSessionStore($pdo, (string)($config['table'] ?? 'auth_sessions'));
    }

    /**
     * @param array<string,mixed> $config
     */
    private static function redisStore(array $config): SessionStoreInterface
    {
        if (!class_exists(\Redis::class)) {
            throw new \RuntimeException('ext-redis is required for RedisSessionStore.');
        }
        $redis = new \Redis();
        $uri = $config['uri'] ?? null;
        if ($uri) {
            $parts = parse_url((string)$uri);
            $host = $parts['host'] ?? '127.0.0.1';
            $port = isset($parts['port']) ? (int)$parts['port'] : 6379;
            $redis->connect($host, $port, (float)($config['timeout'] ?? 1.5));
            if (isset($parts['pass'])) {
                $redis->auth($parts['pass']);
            }
            if (isset($parts['path'])) {
                $db = ltrim($parts['path'], '/');
                if ($db !== '') {
                    $redis->select((int)$db);
                }
            }
        } else {
            $host = (string)($config['host'] ?? '127.0.0.1');
            $port = isset($config['port']) ? (int)$config['port'] : 6379;
            $redis->connect($host, $port, (float)($config['timeout'] ?? 1.5));
            if (!empty($config['password'])) {
                $redis->auth($config['password']);
            }
            if (isset($config['database'])) {
                $redis->select((int)$config['database']);
            }
        }
        $prefix = (string)($config['prefix'] ?? 'auth:sessions');
        return new RedisSessionStore($redis, $prefix);
    }
}
