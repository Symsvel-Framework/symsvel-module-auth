<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

/** Roll back consumption if account state, identity or uniqueness changed. */
final class ProfileEmailChangeUnavailable extends \RuntimeException
{
}
