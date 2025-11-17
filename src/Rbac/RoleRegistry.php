<?php
declare(strict_types=1);

namespace BlackCat\Auth\Rbac;

final class RoleRegistry
{
    /** @var array<string,array{permissions:list<string>,inherits:list<string>}> */
    private array $roles = [];

    public function __construct(array $roles)
    {
        foreach ($roles as $name => $def) {
            $this->roles[$name] = [
                'permissions' => $def['permissions'] ?? [],
                'inherits' => $def['inherits'] ?? [],
            ];
        }
    }

    public static function fromArray(array $roles): self
    {
        return new self($roles);
    }

    /** @return list<string> */
    public function permissions(string $role): array
    {
        $seen = [];
        $stack = [$role];
        while ($stack) {
            $current = array_pop($stack);
            if (isset($seen[$current])) {
                continue;
            }
            $seen[$current] = true;
            $data = $this->roles[$current] ?? null;
            if (!$data) {
                continue;
            }
            foreach ($data['inherits'] as $parent) {
                $stack[] = $parent;
            }
        }
        $perms = [];
        foreach (array_keys($seen) as $name) {
            $perms = array_merge($perms, $this->roles[$name]['permissions'] ?? []);
        }
        return array_values(array_unique($perms));
    }
}
