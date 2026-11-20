<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use SymSvel\Module\Auth\Controller\BoLoginController;
use SymSvel\Module\Auth\Identity\PasswordLogin;

final class BoLoginControllerTest extends TestCase
{
    public function testRejectsUnsupportedContentTypeWithoutCallingLogin(): void
    {
        $response = $this->controller()->__invoke(Request::create('/apibo/auth/login', 'POST', [], [], [], ['CONTENT_TYPE' => 'text/plain'], '{}'));
        self::assertSame(415, $response->getStatusCode());
    }

    public function testRejectsMalformedJsonWithoutCallingLogin(): void
    {
        $response = $this->controller()->__invoke(Request::create('/apibo/auth/login', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{'));
        self::assertSame(400, $response->getStatusCode());
    }

    public function testRejectsMissingCredentialsWithoutCallingLogin(): void
    {
        $response = $this->controller()->__invoke(Request::create('/apibo/auth/login', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{"email":"admin@example.test"}'));
        self::assertSame(400, $response->getStatusCode());
    }

    private function controller(): BoLoginController
    {
        $login = (new \ReflectionClass(PasswordLogin::class))->newInstanceWithoutConstructor();

        return new BoLoginController($login);
    }
}
