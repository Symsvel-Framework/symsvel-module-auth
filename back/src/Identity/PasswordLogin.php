<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenIssuer;
use SymSvel\Module\Auth\Token\TokenPair;

/**
 * Password verification is followed by the optional, registered second-factor
 * policy BEFORE any full session token is issued.
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

        return $this->tokens->issue($subject, $now);
    }
}
