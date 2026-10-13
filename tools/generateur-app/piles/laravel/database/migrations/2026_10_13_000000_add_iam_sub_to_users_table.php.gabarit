<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Lien entre l'utilisateur local et le compte IAM (claim « sub » = users.id
 * dans l'IAM). Les rôles et permissions ne sont PAS stockés ici : ils sont
 * relus de l'IAM à chaque connexion.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('iam_sub', 64)->nullable()->unique()->after('id');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropUnique(['iam_sub']);
            $table->dropColumn('iam_sub');
        });
    }
};
