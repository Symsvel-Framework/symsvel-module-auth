<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/** Immutable Auth module migration compiled by SymSvel Tooling. */
final class Version20200101000500 extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        \SymSvel\Module\Auth\Schema\AuthTokenSchema::apply($schema);
    }

    public function down(Schema $schema): void
    {
        $schema->dropTable('symsvel_auth_refresh_tokens');
        $schema->dropTable('symsvel_auth_access_tokens');
    }
}
