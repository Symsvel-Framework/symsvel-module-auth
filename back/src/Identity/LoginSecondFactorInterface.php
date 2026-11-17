<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

use SymSvel\Module\Auth\Token\TokenSubject;

/**
 * Optional interactive authentication gate. A non-null challenge prevents the
 * issuance of full access/refresh tokens until the owning module verifies it.
 */
interface LoginSecondFactorInterface
{
    public function begin(TokenSubject $subject, \DateTimeImmutable $now): ?SecondFactorChallenge;
}
