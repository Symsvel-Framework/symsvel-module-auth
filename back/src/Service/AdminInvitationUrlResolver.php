<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Service;

final readonly class AdminInvitationUrlResolver
{
    public function __construct(private AuthPageUrls $pages)
    {
    }

    public function resolve(): string
    {
        return $this->pages->forPage('bo', 'invitation');
    }
}
