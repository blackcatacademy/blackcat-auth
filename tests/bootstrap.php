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
