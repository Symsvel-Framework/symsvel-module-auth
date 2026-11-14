<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use Symfony\Component\DependencyInjection\Attribute\TaggedIterator;
use SymSvel\Module\Auth\Token\TokenSubject;

/**
 * Selects an identity owner by context, without a hard dependency on Users.
 * Each tagged provider must implement both identity contracts.
 */
final class ContextIdentityProvider implements PasswordPrincipal, PrincipalStatus
{
    /** @var array<string, PasswordPrincipal&PrincipalStatus> */
    private array $providers = [];

    /** @param iterable<PasswordPrincipal&PrincipalStatus> $providers */
    public function __construct(
        #[TaggedIterator('symsvel.auth.identity_provider')] iterable $providers,
    ) {
        foreach ($providers as $provider) {
            if (!$provider instanceof PasswordPrincipal || !$provider instanceof PrincipalStatus) {
                throw new \LogicException('Auth identity provider must implement both contracts.');
            }
            // Explicit context declaration avoids probing credentials to identify ownership.
            if (!$provider instanceof ContextOwnedIdentity) {
                throw new \LogicException('Auth identity provider must declare its context.');
            }
            $context = $provider->authContext();
            if (!in_array($context, ['bo', 'app'], true) || isset($this->providers[$context])) {
                throw new \LogicException('Invalid or duplicate Auth identity context.');
            }
            $this->providers[$context] = $provider;
        }
    }

    public function authenticate(string $context, string $identifier, string $password): ?TokenSubject
    {
        $provider = $this->providers[$context] ?? null;

        return $provider?->authenticate($context, $identifier, $password);
    }

    public function isActive(TokenSubject $subject): bool
    {
        $provider = $this->providers[$subject->context] ?? null;

        return $provider?->isActive($subject) ?? false;
    }
}
