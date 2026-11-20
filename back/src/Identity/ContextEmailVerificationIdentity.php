<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenSubject;

final class ContextEmailVerificationIdentity
{
    /** @var array<string, EmailVerificationIdentity> */
    private array $providers = [];

    /** @param iterable<EmailVerificationIdentity> $providers */
    public function __construct(iterable $providers)
    {
        foreach ($providers as $provider) {
            $context = $provider->authContext();
            if (!in_array($context, ['bo', 'app'], true) || isset($this->providers[$context])) {
                throw new \LogicException('Invalid or duplicate email verification context.');
            }
            $this->providers[$context] = $provider;
        }
    }

    public function pendingEmail(TokenSubject $subject): ?string
    {
        $email = ($this->providers[$subject->context] ?? null)?->pendingVerificationEmail($subject);

        return is_string($email) && filter_var($email, FILTER_VALIDATE_EMAIL) !== false ? $email : null;
    }

    public function confirm(TokenSubject $subject, string $emailHash, \DateTimeImmutable $now): bool
    {
        if (!preg_match('/^[a-f0-9]{64}$/D', $emailHash)) {
            return false;
        }

        return ($this->providers[$subject->context] ?? null)?->confirmEmail($subject, $emailHash, $now) ?? false;
    }
}
