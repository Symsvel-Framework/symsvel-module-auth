<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use SymSvel\Module\Auth\Schema\ProfileEmailChangeSchema;

/** Verified email change has its own one-time token lifecycle. */
final class Version20261119000012 extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        ProfileEmailChangeSchema::apply($schema);
    }

    public function down(Schema $schema): void
    {
        $schema->dropTable('symsvel_auth_profile_email_changes');
    }
}
