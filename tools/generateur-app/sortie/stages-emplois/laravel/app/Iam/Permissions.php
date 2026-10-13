<?php

namespace App\Iam;

/**
 * Catalogue des permissions de Gestion des Stages et Emplois (stages-emplois).
 *
 * GÉNÉRÉ depuis la base de l'IAM le 2026-10-13 : les codes sont exacts
 * par construction. Une faute de frappe sur un code ne produit aucun
 * avertissement, seulement un 403 à l'exécution — d'où l'intérêt
 * d'utiliser ces constantes plutôt que des chaînes.
 *
 * Pour ajouter une permission : la déclarer dans l'IAM (sql/ ou
 * Administration > Rôles), puis régénérer ce fichier :
 *   python generer.py --app stages-emplois --piles laravel --sortie ... --force
 *
 * 30 permissions, 3 rôles locaux.
 */
final class Permissions
{
    /** Créer une candidature */
    public const CANDIDATURES_CREATE = 'stages-emplois.candidatures.create';

    /** Supprimer une candidature */
    public const CANDIDATURES_DELETE = 'stages-emplois.candidatures.delete';

    /** Modifier une candidature */
    public const CANDIDATURES_EDIT = 'stages-emplois.candidatures.edit';

    /** Exporter les candidatures */
    public const CANDIDATURES_EXPORT = 'stages-emplois.candidatures.export';

    /** Voir les candidatures */
    public const CANDIDATURES_VIEW = 'stages-emplois.candidatures.view';

    /** Créer une convention de stage */
    public const CONVENTIONS_CREATE = 'stages-emplois.conventions.create';

    /** Supprimer une convention de stage */
    public const CONVENTIONS_DELETE = 'stages-emplois.conventions.delete';

    /** Modifier une convention de stage */
    public const CONVENTIONS_EDIT = 'stages-emplois.conventions.edit';

    /** Exporter les conventions de stage */
    public const CONVENTIONS_EXPORT = 'stages-emplois.conventions.export';

    /** Voir les conventions de stage */
    public const CONVENTIONS_VIEW = 'stages-emplois.conventions.view';

    /** Créer un employé */
    public const EMPLOYES_CREATE = 'stages-emplois.employes.create';

    /** Supprimer un employé */
    public const EMPLOYES_DELETE = 'stages-emplois.employes.delete';

    /** Modifier un employé */
    public const EMPLOYES_EDIT = 'stages-emplois.employes.edit';

    /** Exporter les employés */
    public const EMPLOYES_EXPORT = 'stages-emplois.employes.export';

    /** Voir les employés */
    public const EMPLOYES_VIEW = 'stages-emplois.employes.view';

    /** Créer une offre d'emploi */
    public const OFFRES_EMPLOI_CREATE = 'stages-emplois.offres-emploi.create';

    /** Supprimer une offre d'emploi */
    public const OFFRES_EMPLOI_DELETE = 'stages-emplois.offres-emploi.delete';

    /** Modifier une offre d'emploi */
    public const OFFRES_EMPLOI_EDIT = 'stages-emplois.offres-emploi.edit';

    /** Exporter les offres d'emploi */
    public const OFFRES_EMPLOI_EXPORT = 'stages-emplois.offres-emploi.export';

    /** Voir les offres d'emploi */
    public const OFFRES_EMPLOI_VIEW = 'stages-emplois.offres-emploi.view';

    /** Créer un rapport */
    public const RAPPORTS_CREATE = 'stages-emplois.rapports.create';

    /** Supprimer un rapport */
    public const RAPPORTS_DELETE = 'stages-emplois.rapports.delete';

    /** Modifier un rapport */
    public const RAPPORTS_EDIT = 'stages-emplois.rapports.edit';

    /** Exporter les rapports */
    public const RAPPORTS_EXPORT = 'stages-emplois.rapports.export';

    /** Voir les rapports */
    public const RAPPORTS_VIEW = 'stages-emplois.rapports.view';

    /** Créer un stage */
    public const STAGES_CREATE = 'stages-emplois.stages.create';

    /** Supprimer un stage */
    public const STAGES_DELETE = 'stages-emplois.stages.delete';

    /** Modifier un stage */
    public const STAGES_EDIT = 'stages-emplois.stages.edit';

    /** Exporter les stages */
    public const STAGES_EXPORT = 'stages-emplois.stages.export';

    /** Voir les stages */
    public const STAGES_VIEW = 'stages-emplois.stages.view';

    /**
     * Modules de l'application et actions déclarées pour chacun.
     *
     * @var array<string, array{label: string, actions: array<string, string>}>
     */
    public const MODULES = [
        'candidatures' => ['label' => 'Candidatures', 'actions' => ['create' => 'stages-emplois.candidatures.create', 'delete' => 'stages-emplois.candidatures.delete', 'edit' => 'stages-emplois.candidatures.edit', 'export' => 'stages-emplois.candidatures.export', 'view' => 'stages-emplois.candidatures.view']],
        'conventions' => ['label' => 'Conventions de stage', 'actions' => ['create' => 'stages-emplois.conventions.create', 'delete' => 'stages-emplois.conventions.delete', 'edit' => 'stages-emplois.conventions.edit', 'export' => 'stages-emplois.conventions.export', 'view' => 'stages-emplois.conventions.view']],
        'employes' => ['label' => 'Employés', 'actions' => ['create' => 'stages-emplois.employes.create', 'delete' => 'stages-emplois.employes.delete', 'edit' => 'stages-emplois.employes.edit', 'export' => 'stages-emplois.employes.export', 'view' => 'stages-emplois.employes.view']],
        'offres-emploi' => ['label' => 'Offres d\'emploi', 'actions' => ['create' => 'stages-emplois.offres-emploi.create', 'delete' => 'stages-emplois.offres-emploi.delete', 'edit' => 'stages-emplois.offres-emploi.edit', 'export' => 'stages-emplois.offres-emploi.export', 'view' => 'stages-emplois.offres-emploi.view']],
        'rapports' => ['label' => 'Rapports', 'actions' => ['create' => 'stages-emplois.rapports.create', 'delete' => 'stages-emplois.rapports.delete', 'edit' => 'stages-emplois.rapports.edit', 'export' => 'stages-emplois.rapports.export', 'view' => 'stages-emplois.rapports.view']],
        'stages' => ['label' => 'Stages', 'actions' => ['create' => 'stages-emplois.stages.create', 'delete' => 'stages-emplois.stages.delete', 'edit' => 'stages-emplois.stages.edit', 'export' => 'stages-emplois.stages.export', 'view' => 'stages-emplois.stages.view']],
    ];

    /**
     * Matrice rôles × permissions telle que déclarée dans l'IAM au
     * moment de la génération. Sert UNIQUEMENT aux tests
     * (php artisan iam:test-login) : à l'exécution, la seule source de
     * vérité est la liste reçue de l'IAM à la connexion.
     *
     * @var array<string, string[]>
     */
    public const ROLE_MATRIX = [
        'admin' => [
            'stages-emplois.candidatures.create',
            'stages-emplois.candidatures.delete',
            'stages-emplois.candidatures.edit',
            'stages-emplois.candidatures.export',
            'stages-emplois.candidatures.view',
            'stages-emplois.conventions.create',
            'stages-emplois.conventions.delete',
            'stages-emplois.conventions.edit',
            'stages-emplois.conventions.export',
            'stages-emplois.conventions.view',
            'stages-emplois.employes.create',
            'stages-emplois.employes.delete',
            'stages-emplois.employes.edit',
            'stages-emplois.employes.export',
            'stages-emplois.employes.view',
            'stages-emplois.offres-emploi.create',
            'stages-emplois.offres-emploi.delete',
            'stages-emplois.offres-emploi.edit',
            'stages-emplois.offres-emploi.export',
            'stages-emplois.offres-emploi.view',
            'stages-emplois.rapports.create',
            'stages-emplois.rapports.delete',
            'stages-emplois.rapports.edit',
            'stages-emplois.rapports.export',
            'stages-emplois.rapports.view',
            'stages-emplois.stages.create',
            'stages-emplois.stages.delete',
            'stages-emplois.stages.edit',
            'stages-emplois.stages.export',
            'stages-emplois.stages.view',
        ],
        'gestionnaire' => [
            'stages-emplois.candidatures.create',
            'stages-emplois.candidatures.edit',
            'stages-emplois.candidatures.export',
            'stages-emplois.candidatures.view',
            'stages-emplois.conventions.create',
            'stages-emplois.conventions.edit',
            'stages-emplois.conventions.export',
            'stages-emplois.conventions.view',
            'stages-emplois.employes.create',
            'stages-emplois.employes.edit',
            'stages-emplois.employes.export',
            'stages-emplois.employes.view',
            'stages-emplois.offres-emploi.create',
            'stages-emplois.offres-emploi.edit',
            'stages-emplois.offres-emploi.export',
            'stages-emplois.offres-emploi.view',
            'stages-emplois.rapports.create',
            'stages-emplois.rapports.edit',
            'stages-emplois.rapports.export',
            'stages-emplois.rapports.view',
            'stages-emplois.stages.create',
            'stages-emplois.stages.edit',
            'stages-emplois.stages.export',
            'stages-emplois.stages.view',
        ],
        'utilisateur' => [
            'stages-emplois.candidatures.view',
            'stages-emplois.conventions.view',
            'stages-emplois.employes.view',
            'stages-emplois.offres-emploi.view',
            'stages-emplois.rapports.view',
            'stages-emplois.stages.view',
        ],
    ];

    /**
     * Comptes de test déclarés dans l'IAM pour cette application.
     *
     * @var array<int, array{email: string, username: string, name: string, roles: string[]}>
     */
    public const TEST_USERS = [
        ['email' => 'admin.stages-emplois@acsi.local', 'username' => 'admin.stages-emplois', 'name' => 'Admin Stages et Emplois', 'roles' => ['admin']],
        ['email' => 'gestionnaire.stages-emplois@acsi.local', 'username' => 'gestionnaire.stages-emplois', 'name' => 'Gestionnaire Stages et Emplois', 'roles' => ['gestionnaire']],
        ['email' => 'utilisateur.stages-emplois@acsi.local', 'username' => 'utilisateur.stages-emplois', 'name' => 'Utilisateur Stages et Emplois', 'roles' => ['utilisateur']],
    ];

    /** Code complet d'une permission : Permissions::code('contacts', 'edit'). */
    public static function code(string $module, string $action): string
    {
        return 'stages-emplois.'.$module.'.'.$action;
    }
}
