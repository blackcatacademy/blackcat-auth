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
