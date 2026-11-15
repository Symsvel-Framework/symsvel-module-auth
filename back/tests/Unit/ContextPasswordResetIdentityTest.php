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
            public function recoveryEmail(TokenSubject $subject): ?string { return $subject->context === 'bo' && $subject->id === 3 ? 'verified@example.test' : null; }
            public function replacePassword(TokenSubject $subject, string $newPasswordHash): bool { return $subject->context === 'bo'; }
        };
        $router = new ContextPasswordResetIdentity([$bo]);
        self::assertSame(3, $router->find('bo', 'admin@example.test')?->id);
        self::assertNull($router->find('app', 'admin@example.test'));
        self::assertTrue($router->replace(new TokenSubject('bo', 3), 'hash'));
        self::assertFalse($router->replace(new TokenSubject('app', 3), 'hash'));
        self::assertSame('verified@example.test', $router->recoveryEmail(new TokenSubject('bo', 3)));
        self::assertNull($router->recoveryEmail(new TokenSubject('bo', 4)));
        self::assertNull($router->recoveryEmail(new TokenSubject('app', 3)));
    }

    public function testInvalidRecoveryMailboxIsRejected(): void
    {
        $owner = new class implements PasswordResetIdentity {
            public string $email = 'not-an-email';
            public function authContext(): string { return 'bo'; }
            public function findResetSubject(string $identifier): ?TokenSubject { return null; }
            public function recoveryEmail(TokenSubject $subject): ?string { return $this->email; }
            public function replacePassword(TokenSubject $subject, string $newPasswordHash): bool { return false; }
        };
        $router = new ContextPasswordResetIdentity([$owner]);
        $subject = new TokenSubject('bo', 1);
        self::assertNull($router->recoveryEmail($subject));
        $owner->email = 'valid@example.test';
        self::assertSame('valid@example.test', $router->recoveryEmail($subject));
    }

    public function testRejectsDuplicateContext(): void
    {
        $provider = new class implements PasswordResetIdentity {
            public function authContext(): string { return 'bo'; }
            public function findResetSubject(string $identifier): ?TokenSubject { return null; }
            public function recoveryEmail(TokenSubject $subject): ?string { return null; }
            public function replacePassword(TokenSubject $subject, string $newPasswordHash): bool { return false; }
        };
        $this->expectException(\LogicException::class);
        new ContextPasswordResetIdentity([$provider, $provider]);
    }
}
