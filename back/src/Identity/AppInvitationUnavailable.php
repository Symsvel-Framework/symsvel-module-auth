<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

/** Roll back token consumption when the account is not eligible for activation. */
final class AppInvitationUnavailable extends \RuntimeException
{
}

