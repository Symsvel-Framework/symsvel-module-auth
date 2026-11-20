<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenSubject;

/** Exactly one account-owned adapter per installed authentication context. */
final class ContextProfileEmailOwners
{
    /** @var array<string, ProfileEmailOwner> */
    private array $providers = [];

    /** @param iterable<ProfileEmailOwner> $providers */
    public function __construct(iterable $providers)
    {
        foreach ($providers as $provider) {
            $context = $provider->authContext();
            if (!in_array($context, ['bo', 'app'], true) || isset($this->providers[$context])) {
                throw new \LogicException('Invalid or duplicate profile email change owner.');
            }
            $this->providers[$context] = $provider;
        }
    }

    public function confirm(
        TokenSubject $subject,
        string $oldEmailHash,
        string $newEmail,
        \DateTimeImmutable $now,
    ): bool {
        return ($this->providers[$subject->context] ?? null)?->confirmNewEmail(
            $subject, $oldEmailHash, $newEmail, $now,
        ) ?? false;
    }
}
