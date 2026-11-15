<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenSubject;

/** Routes password reset operations to the sole owner of each context. */
final class ContextPasswordResetIdentity
{
    /** @var array<string, PasswordResetIdentity> */
    private array $providers = [];

    /** @param iterable<PasswordResetIdentity> $providers */
    public function __construct(iterable $providers)
    {
        foreach ($providers as $provider) {
            $context = $provider->authContext();
            if (!in_array($context, ['bo', 'app'], true) || isset($this->providers[$context])) {
                throw new \LogicException('Invalid or duplicate password reset context.');
            }
            $this->providers[$context] = $provider;
        }
    }

    public function find(string $context, string $identifier): ?TokenSubject
    {
        $subject = ($this->providers[$context] ?? null)?->findResetSubject($identifier);

        return $subject?->context === $context ? $subject : null;
    }

    public function replace(TokenSubject $subject, string $newPasswordHash): bool
    {
        return ($this->providers[$subject->context] ?? null)?->replacePassword($subject, $newPasswordHash) ?? false;
    }
}
