<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\ContextIdentityProvider;
use SymSvel\Module\Auth\Identity\ContextOwnedIdentity;
use SymSvel\Module\Auth\Identity\PasswordPrincipal;
use SymSvel\Module\Auth\Identity\PrincipalStatus;
use SymSvel\Module\Auth\Token\TokenSubject;

final class ContextIdentityProviderTest extends TestCase
{
    public function testBoOnlyAndOptionalAppContext(): void
    {
        $bo = self::provider('bo');
        $router = new ContextIdentityProvider([$bo]);
        self::assertEquals(new TokenSubject('bo', 10), $router->authenticate('bo', 'a', 'b'));
        self::assertNull($router->authenticate('app', 'a', 'b'));
        self::assertTrue($router->isActive(new TokenSubject('bo', 10)));
        self::assertFalse($router->isActive(new TokenSubject('app', 10)));

        $router = new ContextIdentityProvider([$bo, self::provider('app')]);
        self::assertEquals(new TokenSubject('app', 10), $router->authenticate('app', 'a', 'b'));
    }

    public function testDuplicateContextIsRejected(): void
    {
        $this->expectException(\LogicException::class);
        new ContextIdentityProvider([self::provider('bo'), self::provider('bo')]);
    }

    private static function provider(string $context): PasswordPrincipal&PrincipalStatus&ContextOwnedIdentity
    {
        return new class($context) implements PasswordPrincipal, PrincipalStatus, ContextOwnedIdentity {
            public function __construct(private string $context) {}
            public function authContext(): string { return $this->context; }
            public function authenticate(string $context, string $identifier, string $password): ?TokenSubject
            {
                return $context === $this->context ? new TokenSubject($context, 10) : null;
            }
            public function isActive(TokenSubject $subject): bool { return $subject->context === $this->context; }
        };
    }
}
