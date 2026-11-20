<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/** Dedicated App invitation table, independent from BO tokens. */
final class Version20261116000506 extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        $table = $schema->createTable('symsvel_auth_app_invitations');
        $table->addColumn('id', 'integer', ['autoincrement' => true]);
        $table->addColumn('principal_id', 'integer');
        $table->addColumn('email_hash', 'string', ['length' => 64]);
        $table->addColumn('token_hash', 'string', ['length' => 64]);
        $table->addColumn('expires_at', 'datetime_immutable', ['precision' => 6]);
        $table->addColumn('created_at', 'datetime_immutable', ['precision' => 6]);
        $table->addColumn('used_at', 'datetime_immutable', ['precision' => 6, 'notnull' => false]);
        $table->setPrimaryKey(['id']);
        $table->addUniqueIndex(['token_hash'], 'uniq_symsvel_auth_app_invitation_hash');
        $table->addIndex(['principal_id'], 'idx_symsvel_auth_app_invitation_user');
        $table->addIndex(['expires_at'], 'idx_symsvel_auth_app_invitation_expiry');
    }

    public function down(Schema $schema): void
    {
        $schema->dropTable('symsvel_auth_app_invitations');
    }
}
