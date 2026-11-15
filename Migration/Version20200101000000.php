<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use SymSvel\Module\Auth\Schema\AuthTokenSchema;

/** Immutable Auth module migration compiled by SymSvel Tooling. */
final class Version20200101000000 extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        AuthTokenSchema::apply($schema);
    }

    public function down(Schema $schema): void
    {
        $schema->dropTable('symsvel_auth_refresh_tokens');
        $schema->dropTable('symsvel_auth_access_tokens');
    }
}
