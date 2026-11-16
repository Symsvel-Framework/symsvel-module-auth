<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use SymSvel\Module\Auth\Controller\AppAuthenticationController;
use SymSvel\Module\Auth\Controller\AppEmailVerificationController;

final class AppAuthRoutesTest extends TestCase
{
    public function testAppRouteOwnershipAndIsolation(): void
    {
        $expected = [
            AppAuthenticationController::class => [
                'login' => '/apiopen/auth/login',
                'refresh' => '/apiopen/auth/refresh',
                'me' => '/api/auth/me',
                'logout' => '/api/auth/logout',
            ],
            AppEmailVerificationController::class => [
                'request' => '/apiopen/auth/email-verification/request',
                'complete' => '/apiopen/auth/email-verification/complete',
            ],
        ];
        foreach ($expected as $controller => $routes) {
            foreach ($routes as $method => $path) {
                $attributes = (new \ReflectionMethod($controller, $method))->getAttributes(\Symfony\Component\Routing\Attribute\Route::class);
                self::assertCount(1, $attributes);
                self::assertSame($path, $attributes[0]->getArguments()[0]);
            }
        }
    }

    public function testAppAuthenticationRejectsInvalidBodyBeforeAnyServiceIsCalled(): void
    {
        $controller = (new \ReflectionClass(AppAuthenticationController::class))->newInstanceWithoutConstructor();
        $request = Request::create('/apiopen/auth/login', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{"email":42}');
        self::assertSame(400, $controller->login($request)->getStatusCode());
        $wrongContentType = Request::create('/apiopen/auth/refresh', 'POST');
        self::assertSame(415, $controller->refresh($wrongContentType)->getStatusCode());
        self::assertSame(401, $controller->me(Request::create('/api/auth/me'))->getStatusCode());
        self::assertSame(401, $controller->logout(Request::create('/api/auth/logout', 'POST'))->getStatusCode());
    }

    public function testEmailVerificationRejectsMalformedTokensBeforeConsumption(): void
    {
        $controller = (new \ReflectionClass(AppEmailVerificationController::class))->newInstanceWithoutConstructor();
        $bad = Request::create('/apiopen/auth/email-verification/complete', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{"token":"invalid"}');
        self::assertSame(400, $controller->complete($bad)->getStatusCode());
        self::assertSame(415, $controller->request(Request::create('/apiopen/auth/email-verification/request', 'POST'))->getStatusCode());
    }
}
