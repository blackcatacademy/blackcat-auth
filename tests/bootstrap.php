<?php
declare(strict_types=1);

$repoRoot = dirname(__DIR__);
$monorepoRoot = dirname($repoRoot);

// Monorepo helper: prefer local blackcat-core when present (lets us validate core fixes before pushing).
$localCoreDb = $monorepoRoot . '/blackcat-core/src/Database.php';
if (is_file($localCoreDb)) {
    require_once $localCoreDb;
}

require $repoRoot . '/vendor/autoload.php';

/**
 * Test-only guard rails:
 * - Do not require a full TrustKernel (trust.web3) setup for DB integration tests in this repo.
 * - Production deployments must bootstrap TrustKernel and lock guards; tests intentionally install permissive guards.
 */
if (class_exists('\\BlackCat\\Core\\Database')) {
    if (is_callable(['\\BlackCat\\Core\\Database', 'setWriteGuard'])) {
        \BlackCat\Core\Database::setWriteGuard(static function (string $_sql): void {});
    }
    if (is_callable(['\\BlackCat\\Core\\Database', 'setReadGuard'])) {
        \BlackCat\Core\Database::setReadGuard(static function (string $_sql): void {});
    }
    if (is_callable(['\\BlackCat\\Core\\Database', 'setPdoAccessGuard'])) {
        \BlackCat\Core\Database::setPdoAccessGuard(static function (string $_ctx): void {});
    }
}

/**
 * Helper to set env vars in a PHPUnit-friendly way.
 */
function bcauth_tests_set_env(string $key, string $value): void
{
    if ($value === '') {
        return;
    }
    putenv($key . '=' . $value);
    $_ENV[$key] = $value;
    $_SERVER[$key] = $value;
}

/**
 * Auto-configure DB_DSN for DB integration tests when running on a known Docker network.
 *
 * This keeps integration tests fail-closed (they still fail if no DB is reachable),
 * but avoids requiring manual env export for the common dev setup.
 */
function bcauth_tests_autoconfigure_db_env(): void
{
    $dsn = getenv('DB_DSN');
    if (is_string($dsn) && $dsn !== '') {
        return;
    }

    $user = getenv('DB_USER');
    if (!is_string($user) || $user === '') {
        $user = (string)(getenv('BC_TEST_DB_USER') ?: '');
    }

    $pass = getenv('DB_PASSWORD');
    if (!is_string($pass) || $pass === '') {
        $pass = (string)(getenv('BC_TEST_DB_PASS') ?: '');
    }

    $dbName = getenv('DB_NAME');
    if (!is_string($dbName) || $dbName === '') {
        $dbName = (string)(getenv('BC_TEST_DB_NAME') ?: 'blackcat_test');
    }

    if (extension_loaded('pdo_mysql')) {
        if ($user === '') {
            $user = 'root';
        }
        if ($pass === '') {
            $pass = 'root';
        }

        foreach (['bc-mysql-test', 'bc-mysql', 'mysql', 'mariadb'] as $host) {
            $candidate = sprintf('mysql:host=%s;port=3306;dbname=%s;charset=utf8mb4', $host, $dbName);
            try {
                $options = [
                    \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                    \PDO::ATTR_TIMEOUT => 1,
                ];
                if (defined('\\PDO::MYSQL_ATTR_CONNECT_TIMEOUT')) {
                    $options[\PDO::MYSQL_ATTR_CONNECT_TIMEOUT] = 1;
                }
                $pdo = new \PDO($candidate, $user, $pass, $options);
                $pdo->query('SELECT 1');

                bcauth_tests_set_env('DB_DSN', $candidate);
                bcauth_tests_set_env('DB_USER', $user);
                bcauth_tests_set_env('DB_PASSWORD', $pass);
                return;
            } catch (\Throwable) {
            }
        }
    }

    if (extension_loaded('pdo_pgsql')) {
        if ($user === '') {
            $user = 'postgres';
        }
        if ($pass === '') {
            $pass = 'postgres';
        }

        foreach (['bc-postgres-test', 'bc-postgres', 'postgres'] as $host) {
            $candidate = sprintf('pgsql:host=%s;port=5432;dbname=%s', $host, $dbName);
            try {
                $pdo = new \PDO($candidate, $user, $pass, [
                    \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                    \PDO::ATTR_TIMEOUT => 1,
                ]);
                $pdo->query('SELECT 1');

                bcauth_tests_set_env('DB_DSN', $candidate);
                bcauth_tests_set_env('DB_USER', $user);
                bcauth_tests_set_env('DB_PASSWORD', $pass);
                return;
            } catch (\Throwable) {
            }
        }
    }
}

bcauth_tests_autoconfigure_db_env();

// Test suite default runtime config (fail-closed: no env secrets).
if (class_exists('\\BlackCat\\Config\\Runtime\\Config') && !\BlackCat\Config\Runtime\Config::isInitialized()) {
    $tmpDir = rtrim(sys_get_temp_dir(), '/\\') . '/blackcat-auth-tests-' . bin2hex(random_bytes(8));
    if (!mkdir($tmpDir, 0700, true) && !is_dir($tmpDir)) {
        throw new RuntimeException('tests/bootstrap: unable to create temp dir: ' . $tmpDir);
    }

    $runtimePath = $tmpDir . '/config.runtime.json';
    $runtime = [
        'auth' => [
            // Security-critical keys must live in runtime config (fail-closed).
            'signing_key' => base64_encode(random_bytes(32)),
            'pepper' => base64_encode(random_bytes(32)),
        ],
    ];

    $json = json_encode($runtime, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false || file_put_contents($runtimePath, $json) === false) {
        throw new RuntimeException('tests/bootstrap: unable to write runtime config: ' . $runtimePath);
    }
    @chmod($runtimePath, 0600);

    \BlackCat\Config\Runtime\Config::initFromJsonFile($runtimePath);
}
