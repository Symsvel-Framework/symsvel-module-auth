<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenIssuer;
use SymSvel\Module\Auth\Token\TokenPair;

/**
 * Password authentication followed by atomic token issuance.
 * Never logs or stores raw credentials.
 */
final readonly class PasswordLogin
{
    public function __construct(
        private PasswordPrincipal $principals,
        private TokenIssuer $tokens,
    ) {
    }

    public function login(string $context, string $identifier, string $password, \DateTimeImmutable $now): ?TokenPair
    {
        if (!in_array($context, ['bo', 'app'], true)) {
            return null;
        }

        $subject = $this->principals->authenticate($context, $identifier, $password);
        if ($subject === null || $subject->context !== $context) {
            return null;
        }

        return $this->tokens->issue($subject, $now);
    }
}
