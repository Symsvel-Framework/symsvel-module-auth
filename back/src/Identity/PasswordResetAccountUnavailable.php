<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

/** Internal rollback signal for an account that cannot be updated. */
final class PasswordResetAccountUnavailable extends \RuntimeException
{
}
