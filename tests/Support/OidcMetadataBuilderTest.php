<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Support;

use BlackCat\Auth\Config\AuthConfig;
use BlackCat\Auth\Support\JwksProvider;
use BlackCat\Auth\Support\OidcMetadataBuilder;
use PHPUnit\Framework\TestCase;

final class OidcMetadataBuilderTest extends TestCase
{
    private function config(): AuthConfig
    {
        return new AuthConfig(
            'https://auth.example.com',
            'aud',
            'secret',
            900,
            3600,
            [],
            [],
            300,
            'https://auth.example.com',
            null
        );
    }

    public function testBuildsDiscoveryDocument(): void
    {
        $metadata = OidcMetadataBuilder::build($this->config());
        self::assertSame('https://auth.example.com', $metadata['issuer']);
        self::assertSame('https://auth.example.com/jwks.json', $metadata['jwks_uri']);
        self::assertContains('authorization_code', $metadata['grant_types_supported']);
    }

    public function testProvidesJwks(): void
    {
        $jwks = JwksProvider::fromConfig($this->config());
        self::assertArrayHasKey('keys', $jwks);
        self::assertSame('oct', $jwks['keys'][0]['kty']);
    }
}
