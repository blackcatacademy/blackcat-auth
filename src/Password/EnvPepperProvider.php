<?php
declare(strict_types=1);

namespace BlackCat\Auth\Password;

final class EnvPepperProvider implements PepperProviderInterface
{
    public function __construct(private readonly string $envVar = 'BLACKCAT_AUTH_PEPPER') {}

    public function current(): Pepper
    {
        return $this->load($this->envVar, 'env');
    }

    public function all(): array
    {
        return [$this->current()];
    }

    public function byVersion(string $version): ?Pepper
    {
        return $version === 'env' ? $this->current() : null;
    }

    private function load(string $env, string $version): Pepper
    {
        $value = $_ENV[$env] ?? $_SERVER[$env] ?? null;
        if ($value === null || $value === false || $value === '') {
            try {
                $g = function_exists('getenv') ? getenv($env) : false;
                if ($g !== false && $g !== null) {
                    $value = $g;
                }
            } catch (\Throwable) {
            }
        }

        $value = is_scalar($value) ? (string)$value : '';
        if ($value === '') {
            throw new \RuntimeException(sprintf('Pepper env %s is not set.', $env));
        }
        $raw = base64_decode($value, true);
        if ($raw === false || strlen($raw) !== 32) {
            throw new \RuntimeException('Invalid pepper base64 in ' . $env);
        }
        return new Pepper($raw, $version);
    }
}
