<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use SymSvel\Module\Auth\Browser\TrustedBoOrigin;

final class TrustedBoOriginTest extends TestCase
{
    public function testRequiresExactHttpsBoOrigin(): void
    {
        $origin = new TrustedBoOrigin(sys_get_temp_dir().'/missing-backend', 'https://bo.example.test');
        foreach (['https://app.example.test', 'http://bo.example.test', 'https://bo.example.test.evil.test', ''] as $untrusted) {
            $request = Request::create('/apibo/auth/browser/refresh', 'POST');
            if ($untrusted !== '') {
                $request->headers->set('Origin', $untrusted);
            }
            self::assertFalse($origin->accepts($request));
        }
        $request = Request::create('/apibo/auth/browser/refresh', 'POST');
        $request->headers->set('Origin', 'https://bo.example.test');
        self::assertTrue($origin->accepts($request));
    }

    public function testDerivesBoOriginFromWorkspaceSetupMetadata(): void
    {
        $workspace = sys_get_temp_dir().'/symsvel-bo-origin-'.bin2hex(random_bytes(6));
        mkdir($workspace.'/.symsvel', 0700, true);
        mkdir($workspace.'/backend', 0700);
        try {
            $request = Request::create('/apibo/auth/browser/login', 'POST');
            $request->headers->set('Origin', 'https://bo.xt.localhost');
            $origin = new TrustedBoOrigin($workspace.'/backend');
            self::assertFalse($origin->accepts($request));
            file_put_contents($workspace.'/.symsvel/project.json', '{"schema":1,"local_domain":"xt.localhost"}');
            self::assertTrue($origin->accepts($request));
            file_put_contents($workspace.'/.symsvel/project.json', '{"schema":1,"local_domain":"bad/path"}');
            self::assertFalse($origin->accepts($request));
        } finally {
            @unlink($workspace.'/.symsvel/project.json');
            rmdir($workspace.'/backend');
            rmdir($workspace.'/.symsvel');
            rmdir($workspace);
        }
    }

    public function testExplicitMalformedOriginFailsClosed(): void
    {
        $origin = new TrustedBoOrigin('/unused', 'https://bo.example.test/path');
        $request = Request::create('/apibo/auth/browser/login', 'POST');
        $request->headers->set('Origin', 'https://bo.example.test/path');
        self::assertFalse($origin->accepts($request));
    }

    public function testDevAcceptsSetupLocalHttpAndPortsWithoutTrustingForeignOrigins(): void
    {
        $workspace = sys_get_temp_dir().'/symsvel-origin-http-'.bin2hex(random_bytes(6));
        mkdir($workspace.'/.symsvel', 0700, true);
        mkdir($workspace.'/backend', 0700);
        try {
            file_put_contents($workspace.'/.symsvel/project.json', '{"schema":1,"local_domain":"xt.localhost"}');
            $dev = new TrustedBoOrigin($workspace.'/backend', null, 'dev');
            $prod = new TrustedBoOrigin($workspace.'/backend', null, 'prod');
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

            foreach ([
                'http://app.xt.localhost',
                'http://bo.xt.localhost.evil.example',
                'http://bo.xt.localhost/path',
                'null',
                'http://bo.xt.localhost:99999',
            ] as $untrusted) {
                $request->headers->set('Origin', $untrusted);
                self::assertFalse($dev->accepts($request), $untrusted);
            }

            file_put_contents($workspace.'/.symsvel/project.json', '{"schema":1,"local_domain":"example.com"}');
            $request->headers->set('Origin', 'http://bo.example.com');
            self::assertFalse($dev->accepts($request));

            file_put_contents($workspace.'/.symsvel/project.json', '{"schema":1,"local_domain":"xt.localhost"}');
            $request->headers->set('Origin', 'http://bo.xt.localhost');
            $secureRequest = Request::create('https://backend.xt.localhost/apibo/auth/browser/login', 'POST');
            $secureRequest->headers->set('Origin', 'http://bo.xt.localhost');
            self::assertFalse($dev->accepts($secureRequest));
        } finally {
            @unlink($workspace.'/.symsvel/project.json');
            rmdir($workspace.'/backend');
            rmdir($workspace.'/.symsvel');
            rmdir($workspace);
        }
    }

}
