<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\ContextPasswordResetIdentity;
use SymSvel\Module\Auth\Identity\PasswordResetIdentity;
use SymSvel\Module\Auth\Token\TokenSubject;

final class ContextPasswordResetIdentityTest extends TestCase
{
    public function testRoutesOnlyToOwningContext(): void
    {
        $bo = new class implements PasswordResetIdentity {
            public function authContext(): string { return 'bo'; }
            public function findResetSubject(string $identifier): ?TokenSubject { return new TokenSubject('bo', 3); }
            public function replacePassword(TokenSubject $subject, string $newPasswordHash): bool { return $subject->context === 'bo'; }
        };
        $router = new ContextPasswordResetIdentity([$bo]);
        self::assertSame(3, $router->find('bo', 'admin@example.test')?->id);
        self::assertNull($router->find('app', 'admin@example.test'));
        self::assertTrue($router->replace(new TokenSubject('bo', 3), 'hash'));
        self::assertFalse($router->replace(new TokenSubject('app', 3), 'hash'));
    }

    public function testRejectsDuplicateContext(): void
    {
        $provider = new class implements PasswordResetIdentity {
            public function authContext(): string { return 'bo'; }
            public function findResetSubject(string $identifier): ?TokenSubject { return null; }
            public function replacePassword(TokenSubject $subject, string $newPasswordHash): bool { return false; }
        };
        $this->expectException(\LogicException::class);
        new ContextPasswordResetIdentity([$provider, $provider]);
    }
}
