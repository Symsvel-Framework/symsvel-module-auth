<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use SymSvel\Module\Auth\Browser\TrustedBoOrigin;

final class TrustedBoOriginTest extends TestCase
{
    public function testExplicitHttpsOverrideRequiresExactOrigin(): void
    {
        $origin = new TrustedBoOrigin('prod', null, 'https://bo.example.test');
        foreach (['https://app.example.test', 'http://bo.example.test',
            'https://bo.example.test.evil.test', '', 'https://bo.example.test/path'] as $untrusted) {
            $request = Request::create('/apibo/auth/browser/refresh', 'POST');
            if ($untrusted !== '') {
                $request->headers->set('Origin', $untrusted);
            }
            self::assertFalse($origin->accepts($request), $untrusted);
        }
        $request = Request::create('/apibo/auth/browser/refresh', 'POST');
        $request->headers->set('Origin', 'https://bo.example.test');
        self::assertTrue($origin->accepts($request));
    }

    public function testRuntimeDomainWorksWithoutReadingOwnerOnlyWorkspaceMetadata(): void
    {
        // Same configuration is available from .env.local to PHP-FPM.
        // There is deliberately no readable workspace project.json.
        $origin = new TrustedBoOrigin('prod', 'xt.localhost');
        $request = Request::create('https://backend.xt.localhost/apibo/auth/browser/login', 'POST');
        $request->headers->set('Origin', 'https://bo.xt.localhost');
        self::assertTrue($origin->accepts($request));

        $unconfigured = new TrustedBoOrigin('prod', null);
        $previous = $_SERVER['SYMSVEL_BO_DOMAIN'] ?? null;
        $hadPrevious = array_key_exists('SYMSVEL_BO_DOMAIN', $_SERVER);
        try {
            unset($_SERVER['SYMSVEL_BO_DOMAIN']);
            self::assertFalse($unconfigured->accepts($request));
            $_SERVER['SYMSVEL_BO_DOMAIN'] = 'xt.localhost';
            self::assertTrue($unconfigured->accepts($request));
            $_SERVER['SYMSVEL_BO_DOMAIN'] = 'invalid/path';
            self::assertFalse($unconfigured->accepts($request));
        } finally {
            if ($hadPrevious) {
                $_SERVER['SYMSVEL_BO_DOMAIN'] = $previous;
            } else {
                unset($_SERVER['SYMSVEL_BO_DOMAIN']);
            }
        }
    }

    public function testDevAcceptsOnlySetupMatchedLocalOrigins(): void
    {
        $dev = new TrustedBoOrigin('dev', 'xt.localhost');
        $prod = new TrustedBoOrigin('prod', 'xt.localhost');
        $request = Request::create('http://backend.xt.localhost/apibo/auth/browser/login', 'POST');
        $request->headers->set('Origin', 'http://bo.xt.localhost');
        self::assertTrue($dev->accepts($request));
        self::assertTrue($dev->usesLocalHttpCookie($request));
        self::assertFalse($prod->accepts($request));

        $request->headers->set('Origin', 'http://bo.xt.localhost:5173');
        self::assertTrue($dev->accepts($request));
        $request->headers->set('Origin', 'https://bo.xt.localhost:5173');
        self::assertTrue($dev->accepts($request));
        self::assertFalse($dev->usesLocalHttpCookie($request));
        self::assertFalse($prod->accepts($request));

        foreach (['http://app.xt.localhost', 'http://bo.xt.localhost.evil.example',
            'http://bo.xt.localhost/path', 'null', 'http://bo.xt.localhost:99999'] as $untrusted) {
            $request->headers->set('Origin', $untrusted);
            self::assertFalse($dev->accepts($request), $untrusted);
        }
        $request = Request::create('https://backend.xt.localhost/apibo/auth/browser/login', 'POST');
        $request->headers->set('Origin', 'http://bo.xt.localhost');
        self::assertFalse($dev->accepts($request));
    }

    public function testDevMayUseCustomSetupDomainOverLoopbackOnly(): void
    {
        $dev = new TrustedBoOrigin('dev', 'www.example.fr');
        $request = Request::create('http://backend.www.example.fr/apibo/auth/browser/login', 'POST');
        $request->headers->set('Origin', 'http://bo.www.example.fr');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');
        self::assertTrue($dev->accepts($request));
        self::assertTrue($dev->usesLocalHttpCookie($request));
        $request->server->set('REMOTE_ADDR', '192.0.2.10');
        self::assertFalse($dev->accepts($request));
        self::assertFalse((new TrustedBoOrigin('prod', 'www.example.fr'))->accepts($request));
    }

    public function testExplicitMalformedOverrideFailsClosed(): void
    {
        $request = Request::create('/apibo/auth/browser/login', 'POST');
        $request->headers->set('Origin', 'https://bo.example.test/path');
        self::assertFalse((new TrustedBoOrigin('prod', null, 'https://bo.example.test/path'))->accepts($request));
    }
}
