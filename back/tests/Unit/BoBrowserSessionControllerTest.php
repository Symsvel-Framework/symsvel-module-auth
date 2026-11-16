<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use SymSvel\Module\Auth\Browser\TrustedBoOrigin;
use SymSvel\Module\Auth\Controller\BoBrowserSessionController;
use SymSvel\Module\Auth\Identity\PasswordLogin;
use SymSvel\Module\Auth\Token\IssuedToken;
use SymSvel\Module\Auth\Token\TokenLogout;
use SymSvel\Module\Auth\Token\TokenPair;
use SymSvel\Module\Auth\Token\TokenRotation;

final class BoBrowserSessionControllerTest extends TestCase
{
    private function controller(): BoBrowserSessionController
    {
        $blank = static fn (string $class): object => (new \ReflectionClass($class))->newInstanceWithoutConstructor();
        return new BoBrowserSessionController(
            new TrustedBoOrigin('/unused', 'https://bo.example.test'),
            $blank(PasswordLogin::class),
            $blank(TokenRotation::class),
            $blank(TokenLogout::class),
        );
    }

    private static function request(string $operation, ?string $origin = 'https://bo.example.test'): Request
    {
        $request = Request::create('/apibo/auth/browser/'.$operation, 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{}');
        if ($origin !== null) {
            $request->headers->set('Origin', $origin);
        }
        return $request;
    }

    public function testMissingOrUntrustedOriginCannotAccessAnyBrowserSessionEndpoint(): void
    {
        $controller = $this->controller();
        foreach ([null, 'https://app.example.test'] as $origin) {
            self::assertSame(403, $controller->login(self::request('login', $origin))->getStatusCode());
            self::assertSame(403, $controller->refresh(self::request('refresh', $origin))->getStatusCode());
            self::assertSame(403, $controller->logout(self::request('logout', $origin))->getStatusCode());
        }
    }

    public function testRefreshRequiresCookieAndLogoutClearsIt(): void
    {
        $controller = $this->controller();
        $unauthorized = $controller->refresh(self::request('refresh'));
        self::assertSame(401, $unauthorized->getStatusCode());
        $cookie = $unauthorized->headers->getCookies()[0];
        self::assertTrue($cookie->isHttpOnly());
        self::assertTrue($cookie->isSecure());
        self::assertSame('/', $cookie->getPath());
        self::assertSame('strict', strtolower((string) $cookie->getSameSite()));
        self::assertNull($cookie->getDomain());
        self::assertSame(204, $controller->logout(self::request('logout'))->getStatusCode());
    }

    public function testLoginRejectsMalformedBodyWithoutTouchingCredentials(): void
    {
        self::assertSame(400, $this->controller()->login(self::request('login'))->getStatusCode());
    }

    public function testBrowserTokenJsonDoesNotExposeRefreshSecret(): void
    {
        $now = new \DateTimeImmutable('2099-01-01T00:00:00Z');
        $pair = new TokenPair(
            'bo', 'family', new IssuedToken(str_repeat('a', 43), 'hash1', $now),
            new IssuedToken(str_repeat('b', 43), 'hash2', $now),
        );
        $method = new \ReflectionMethod(BoBrowserSessionController::class, 'pairResponse');
        $response = $method->invoke(null, $pair);
        self::assertSame(200, $response->getStatusCode());
        self::assertStringNotContainsString(str_repeat('b', 43), (string) $response->getContent());
        self::assertArrayNotHasKey('refresh_token', json_decode((string) $response->getContent(), true, 8, JSON_THROW_ON_ERROR));
        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        $cookie = $response->headers->getCookies()[0];
        self::assertSame(str_repeat('b', 43), $cookie->getValue());
        self::assertTrue($cookie->isHttpOnly());
        self::assertTrue($cookie->isSecure());
        self::assertSame('strict', strtolower((string) $cookie->getSameSite()));
    }
}
