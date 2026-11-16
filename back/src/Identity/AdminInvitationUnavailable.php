<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

/** Triggers rollback when the invited account cannot be activated. */
final class AdminInvitationUnavailable extends \RuntimeException
{
}
