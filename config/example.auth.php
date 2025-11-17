<?php

declare(strict_types=1);

return [
    'config_profile' => [
        'file' => dirname(__DIR__) . '/../blackcat-config/config/profiles.php',
        'environment' => 'development',
    ],
    'auth' => [
        'issuer' => 'https://auth.blackcat.local',
        'audience' => 'blackcat-clients',
        'signing_key' => '${env:BLACKCAT_AUTH_SIGNING_KEY}',
        'access_ttl' => 900,
        'refresh_ttl' => 604800,
        'public_base_url' => 'https://auth.blackcat.local',
        'pkce_window' => 300,
        'session' => [
            'ttl' => 3600,
        ],
        'magic_link' => [
            'ttl' => 900,
            'url' => 'https://auth.blackcat.local/magic-login',
        ],
        'events' => [
            'buffer_size' => 200,
            'webhooks' => [],
        ],
        'roles' => [
            'admin' => ['permissions' => ['*']],
            'service' => ['permissions' => ['tokens:create']],
        ],
        'clients' => [
            'service-api' => [
                'secret' => '${env:BLACKCAT_SERVICE_API_SECRET}',
                'roles' => ['service'],
                'scopes' => ['sync'],
            ],
        ],
    ],
    'user_store' => [
        'driver' => 'database',
        'dsn' => 'sqlite:' . __DIR__ . '/../var/auth.sqlite',
        'table' => 'users',
        'id_column' => 'id',
        'email_column' => 'email',
        'password_column' => 'password',
        'roles_column' => 'roles',
        'status_column' => 'status',
        'status_active_value' => 'active',
        'pepper_env' => 'BLACKCAT_AUTH_PEPPER',
    ],
    'seed_users' => [
        [
            'id' => 'demo-admin',
            'email' => 'admin@example.com',
            'password' => 'secret',
            'roles' => ['admin'],
        ],
    ],
    'telemetry' => [
        'prometheus_file' => __DIR__ . '/../var/metrics.prom',
    ],
    'cli' => [
        'default_roles' => ['admin'],
    ],
];
