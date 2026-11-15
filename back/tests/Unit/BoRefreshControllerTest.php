<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use SymSvel\Module\Auth\Controller\BoRefreshController;
use SymSvel\Module\Auth\Token\TokenRotation;

final class BoRefreshControllerTest extends TestCase
{
    public function testMissingJsonContentTypeIsRejected(): void
    {
        $response = $this->controller()->__invoke(Request::create('/apibo/auth/refresh', 'POST'));
        self::assertSame(415, $response->getStatusCode());
    }

    public function testMalformedJsonIsRejected(): void
    {
        $request = Request::create('/apibo/auth/refresh', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{');
        self::assertSame(400, $this->controller()->__invoke($request)->getStatusCode());
    }

    public function testInvalidRefreshTokenIsRejectedBeforeRotation(): void
    {
        $request = Request::create('/apibo/auth/refresh', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{"refresh_token":"invalid"}');
        self::assertSame(400, $this->controller()->__invoke($request)->getStatusCode());
    }

    private function controller(): BoRefreshController
    {
        $rotation = (new \ReflectionClass(TokenRotation::class))->newInstanceWithoutConstructor();

        return new BoRefreshController($rotation);
    }
}
