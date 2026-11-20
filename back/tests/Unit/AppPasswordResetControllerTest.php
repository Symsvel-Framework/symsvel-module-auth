<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use SymSvel\Module\Auth\Controller\AppPasswordResetController;

final class AppPasswordResetControllerTest extends TestCase
{
    public function testRoutesAndRequestValidationWithoutServiceAccess(): void
    {
        $controller = (new \ReflectionClass(AppPasswordResetController::class))->newInstanceWithoutConstructor();
        foreach ([
            'request' => '/apiopen/auth/password-reset/request',
            'complete' => '/apiopen/auth/password-reset/complete',
        ] as $method => $path) {
            $attrs = (new \ReflectionMethod(AppPasswordResetController::class, $method))
                ->getAttributes(\Symfony\Component\Routing\Attribute\Route::class);
            self::assertCount(1, $attrs);
            self::assertSame($path, $attrs[0]->getArguments()[0]);
        }
        self::assertSame(415, $controller->request(Request::create('/apiopen/auth/password-reset/request', 'POST'))->getStatusCode());
        self::assertSame(400, $controller->request(self::json('/apiopen/auth/password-reset/request', ['email' => 'bad']))->getStatusCode());
        self::assertSame(400, $controller->complete(self::json('/apiopen/auth/password-reset/complete', [
            'token' => 'bad', 'password' => 'correct-password-123',
        ]))->getStatusCode());
        self::assertSame(400, $controller->complete(self::json('/apiopen/auth/password-reset/complete', [
            'token' => str_repeat('A', 43), 'password' => 'short',
        ]))->getStatusCode());
        self::assertSame(400, $controller->complete(self::json('/apiopen/auth/password-reset/complete', [
            'token' => str_repeat('A', 43), 'password' => "long-enough\0password",
        ]))->getStatusCode());
    }

    private static function json(string $path, array $data): Request
    {
        return Request::create(
            $path, 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'],
            json_encode($data, JSON_THROW_ON_ERROR),
        );
    }
}
