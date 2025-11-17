<?php
declare(strict_types=1);

namespace BlackCat\Auth\WebAuthn;

interface WebAuthnStoreInterface
{
    /**
     * @param list<WebAuthnCredential> $credentials
     */
    public function saveCredentials(string $subject, array $credentials): void;

    /**
     * @return list<WebAuthnCredential>
     */
    public function loadCredentials(string $subject): array;

    public function rememberChallenge(string $challenge, array $metadata): void;

    public function consumeChallenge(string $challenge): ?array;
}
