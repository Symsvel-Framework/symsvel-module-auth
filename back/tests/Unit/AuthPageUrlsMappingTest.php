<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Service\AuthPageUrls;

final class AuthPageUrlsMappingTest extends TestCase
{
    public function testProductionUsesAppAndBoMappedOrigins(): void
    {
        $urls = new AuthPageUrls(
            'prod', 'choralys.com',
            'https://admin.choralys.com', 'https://manager.choralys.com',
        );
        self::assertSame('https://manager.choralys.com/activate', $urls->forPage('app', 'invitation'));
        self::assertSame('https://manager.choralys.com/reset-password', $urls->forPage('app', 'reset'));
        self::assertSame('https://admin.choralys.com/auth/activate', $urls->forPage('bo', 'invitation'));
    }

    public function testMappedLocalHttpAppMayUseAnotherReservedSubdomain(): void
    {
        $urls = new AuthPageUrls(
            'dev', 'xt.localhost',
            'http://administration.xt.localhost:5173', 'http://manager.xt.localhost:5174',
        );
        self::assertSame('http://manager.xt.localhost:5174/activate', $urls->forPage('app', 'invitation'));
        self::assertSame('http://administration.xt.localhost:5173/reset-password', $urls->forPage('bo', 'reset'));
    }

    public function testPublicHttpCustomAppDomainIsRejected(): void
    {
        $urls = new AuthPageUrls('prod', 'choralys.com', null, 'http://manager.choralys.com');
        $this->expectException(\LogicException::class);
        $urls->forPage('app', 'invitation');
    }
}
