<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenIssuer;
use SymSvel\Module\Auth\Token\TokenPair;

/**
 * Password verification precedes the factor policy. BO always requires a
 * challenge; App keeps optional second-factor enrollment.
 */
final readonly class PasswordLogin
{
    /** @var list<LoginSecondFactorInterface> */
    private array $secondFactors;

    /** @param iterable<LoginSecondFactorInterface> $secondFactors */
    public function __construct(
        private PasswordPrincipal $principals,
        private TokenIssuer $tokens,
        iterable $secondFactors = [],
    ) {
        $providers = [];
        foreach ($secondFactors as $provider) {
            if (!$provider instanceof LoginSecondFactorInterface) {
                throw new \LogicException('Invalid second-factor provider.');
            }
            $providers[] = $provider;
        }
        if (count($providers) > 1) {
            throw new \LogicException('Multiple second-factor providers are not supported.');
        }
        $this->secondFactors = $providers;
    }

    public function completeSecondFactor(string $context, string $challenge, string $code, \DateTimeImmutable $now): ?SecondFactorVerified
    {
        if (!in_array($context, ['bo', 'app'], true)) {
            return null;
        }
        foreach ($this->secondFactors as $factor) {
            return $factor->complete($context, $challenge, $code, $now);
        }
        return null;
    }

    public function login(string $context, string $identifier, string $password, \DateTimeImmutable $now): TokenPair|SecondFactorChallenge|null
    {
        if (!in_array($context, ['bo', 'app'], true)) {
            return null;
        }

        $subject = $this->principals->authenticate($context, $identifier, $password);
        if ($subject === null || $subject->context !== $context) {
            return null;
        }

        foreach ($this->secondFactors as $factor) {
            $challenge = $factor->begin($subject, $now);
            if ($challenge !== null) {
                return $challenge;
            }
        }

        // Fail closed: an absent or permissive provider must never let a BO
        // session bypass the administrator's mandatory second factor.
        if ($context === 'bo') {
            throw new \LogicException('BO requires a registered second-factor provider that issues a challenge.');
        }

        if ($this->principals instanceof TransactionalPrincipalStatus) {
            return $this->tokens->issueWhen($subject, $now, fn (): bool => $this->principals->lockActive($subject));
        }
        return $this->tokens->issue($subject, $now);
    }
}
