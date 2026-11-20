<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use SymSvel\Module\Auth\Controller\BoSessionController;
use SymSvel\Module\Auth\Identity\AuthenticatedTokenResolver;

final class BoSessionControllerTest extends TestCase
{
    public function testMissingBearerIsRejectedBeforeTokenLookup(): void
    {
        $response = $this->controller()->__invoke(Request::create('/apibo/auth/me'));
        self::assertSame(401, $response->getStatusCode());
        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
    }

    public function testMalformedBearerIsRejectedBeforeTokenLookup(): void
    {
        $request = Request::create('/apibo/auth/me');
        $request->headers->set('Authorization', 'Bearer malformed');
        self::assertSame(401, $this->controller()->__invoke($request)->getStatusCode());
    }

    private function controller(): BoSessionController
    {
        $resolver = (new \ReflectionClass(AuthenticatedTokenResolver::class))->newInstanceWithoutConstructor();

        return new BoSessionController($resolver);
    }
}
