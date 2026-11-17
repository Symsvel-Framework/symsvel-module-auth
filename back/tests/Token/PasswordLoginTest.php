<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\PasswordLogin;
use SymSvel\Module\Auth\Identity\LoginSecondFactorInterface;
use SymSvel\Module\Auth\Identity\SecondFactorChallenge;
use SymSvel\Module\Auth\Identity\SecondFactorVerified;
use SymSvel\Module\Auth\Identity\PasswordPrincipal;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenIssuer;
use SymSvel\Module\Auth\Token\TokenSubject;

final class PasswordLoginTest extends TestCase
{
    public function testOnlyAuthenticatedMatchingContextIssuesTokens(): void
    {
        $principal = new class implements PasswordPrincipal {
            public int $calls = 0;
            public ?TokenSubject $subject = null;

            public function authenticate(string $context, string $identifier, string $password): ?TokenSubject
            {
                ++$this->calls;
                return $this->subject;
            }
        };
        $store = new InMemoryTokenStore();
        $login = new PasswordLogin($principal, new TokenIssuer($store, new TokenFactory()));
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');

        self::assertNull($login->login('invalid', 'a@example.com', 'secret', $now));
        self::assertSame(0, $principal->calls);
        self::assertSame(0, $store->transactions);

        self::assertNull($login->login('bo', 'a@example.com', 'wrong', $now));
        self::assertSame(0, $store->transactions);

        $principal->subject = new TokenSubject('app', 5);
        self::assertNull($login->login('bo', 'a@example.com', 'secret', $now));
        self::assertSame(0, $store->transactions);

        $principal->subject = new TokenSubject('app', 5);
        $pair = $login->login('app', 'a@example.com', 'secret', $now);
        self::assertNotNull($pair);
        self::assertSame('app', $pair->context);
        self::assertSame(1, $store->transactions);
        self::assertSame(['save'], $store->operations);
    }
    public function testOptionalSecondFactorBlocksSessionUntilVerified(): void
    {
        $principal = new class implements PasswordPrincipal {
            public function authenticate(string $context, string $identifier, string $password): ?TokenSubject
            {
                return $password === 'valid' ? new TokenSubject('bo', 17) : null;
            }
        };
        $provider = new class implements LoginSecondFactorInterface {
            public int $begins = 0;
            public function begin(TokenSubject $subject, \DateTimeImmutable $now): ?SecondFactorChallenge
            {
                ++$this->begins;
                return new SecondFactorChallenge(str_repeat('A', 43), $now->modify('+5 minutes'));
            }
            public function complete(string $context, string $challenge, string $code, \DateTimeImmutable $now): ?SecondFactorVerified
            {
                return null;
            }
        };

        $store = new InMemoryTokenStore();
        $login = new PasswordLogin($principal, new TokenIssuer($store, new TokenFactory()), [$provider]);
        $now = new \DateTimeImmutable('2026-11-17T10:00:00+00:00');
        self::assertNull($login->login('bo', 'admin@example.test', 'wrong', $now));
        self::assertSame(0, $provider->begins);

        $result = $login->login('bo', 'admin@example.test', 'valid', $now);
        self::assertInstanceOf(SecondFactorChallenge::class, $result);
        self::assertSame(1, $provider->begins);
        self::assertSame(0, $store->transactions);
        self::assertSame([], $store->operations);
        self::assertTrue($result->response()['second_factor_required']);
        self::assertNull($login->completeSecondFactor('bo', $result->challenge, '123456', $now));
        self::assertSame(0, $store->transactions);
    }

    public function testDuplicateSecondFactorProvidersAreRejected(): void
    {
        $provider = new class implements LoginSecondFactorInterface {
            public function begin(TokenSubject $subject, \DateTimeImmutable $now): ?SecondFactorChallenge { return null; }
            public function complete(string $context, string $challenge, string $code, \DateTimeImmutable $now): ?SecondFactorVerified { return null; }
        };
        $principal = new class implements PasswordPrincipal {
            public function authenticate(string $context, string $identifier, string $password): ?TokenSubject { return null; }
        };
        $this->expectException(\LogicException::class);
        new PasswordLogin($principal, new TokenIssuer(new InMemoryTokenStore(), new TokenFactory()),
            [$provider, $provider]);
    }

    public function testBoCannotLoginWithoutAnEnforcingSecondFactorProvider(): void
    {
        $principal = new class implements PasswordPrincipal {
            public function authenticate(string $context, string $identifier, string $password): ?TokenSubject
            {
                return $password === 'valid' ? new TokenSubject($context, 21) : null;
            }
        };
        $store = new InMemoryTokenStore();
        $issuer = new TokenIssuer($store, new TokenFactory());
        $now = new \DateTimeImmutable('2026-11-17T10:00:00+00:00');

        foreach ([
            new PasswordLogin($principal, $issuer),
            new PasswordLogin($principal, $issuer, [
                new class implements LoginSecondFactorInterface {
                    public function begin(TokenSubject $subject, \DateTimeImmutable $now): ?SecondFactorChallenge
                    {
                        return null;
                    }
                    public function complete(string $context, string $challenge, string $code, \DateTimeImmutable $now): ?SecondFactorVerified
                    {
                        return null;
                    }
                },
            ]),
        ] as $login) {
            try {
                $login->login('bo', 'admin@example.test', 'valid', $now);
                self::fail('BO login must fail closed without a challenge.');
            } catch (\LogicException $e) {
                self::assertStringContainsString('second-factor provider', $e->getMessage());
            }
        }

        self::assertSame(0, $store->transactions);
        self::assertSame([], $store->operations);
        self::assertNotNull((new PasswordLogin($principal, $issuer))->login('app', 'user@example.test', 'valid', $now));
    }

}
