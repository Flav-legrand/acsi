<?php

namespace App\Iam;

/**
 * Catalogue des permissions de Gestion des Partenaires (partenaires).
 *
 * GÉNÉRÉ depuis la base de l'IAM le 2026-10-13 : les codes sont exacts
 * par construction. Une faute de frappe sur un code ne produit aucun
 * avertissement, seulement un 403 à l'exécution — d'où l'intérêt
 * d'utiliser ces constantes plutôt que des chaînes.
 *
 * Pour ajouter une permission : la déclarer dans l'IAM (sql/ ou
 * Administration > Rôles), puis régénérer ce fichier :
 *   python generer.py --app partenaires --piles laravel --sortie ... --force
 *
 * 25 permissions, 3 rôles locaux.
 */
final class Permissions
{
    /** Créer un contact */
    public const CONTACTS_CREATE = 'partenaires.contacts.create';

    /** Supprimer un contact */
    public const CONTACTS_DELETE = 'partenaires.contacts.delete';

    /** Modifier un contact */
    public const CONTACTS_EDIT = 'partenaires.contacts.edit';

    /** Exporter les contacts */
    public const CONTACTS_EXPORT = 'partenaires.contacts.export';

    /** Voir les contacts */
    public const CONTACTS_VIEW = 'partenaires.contacts.view';

    /** Créer une convention */
    public const CONVENTIONS_CREATE = 'partenaires.conventions.create';

    /** Supprimer une convention */
    public const CONVENTIONS_DELETE = 'partenaires.conventions.delete';

    /** Modifier une convention */
    public const CONVENTIONS_EDIT = 'partenaires.conventions.edit';

    /** Exporter les conventions */
    public const CONVENTIONS_EXPORT = 'partenaires.conventions.export';

    /** Voir les conventions */
    public const CONVENTIONS_VIEW = 'partenaires.conventions.view';

    /** Créer un document */
    public const DOCUMENTS_CREATE = 'partenaires.documents.create';

    /** Supprimer un document */
    public const DOCUMENTS_DELETE = 'partenaires.documents.delete';

    /** Modifier un document */
    public const DOCUMENTS_EDIT = 'partenaires.documents.edit';

    /** Exporter les documents */
    public const DOCUMENTS_EXPORT = 'partenaires.documents.export';

    /** Voir les documents */
    public const DOCUMENTS_VIEW = 'partenaires.documents.view';

    /** Créer un partenaire */
    public const PARTENAIRES_CREATE = 'partenaires.partenaires.create';

    /** Supprimer un partenaire */
    public const PARTENAIRES_DELETE = 'partenaires.partenaires.delete';

    /** Modifier un partenaire */
    public const PARTENAIRES_EDIT = 'partenaires.partenaires.edit';

    /** Exporter les partenaires */
    public const PARTENAIRES_EXPORT = 'partenaires.partenaires.export';

    /** Voir les partenaires */
    public const PARTENAIRES_VIEW = 'partenaires.partenaires.view';

    /** Créer un rapport */
    public const RAPPORTS_CREATE = 'partenaires.rapports.create';

    /** Supprimer un rapport */
    public const RAPPORTS_DELETE = 'partenaires.rapports.delete';

    /** Modifier un rapport */
    public const RAPPORTS_EDIT = 'partenaires.rapports.edit';

    /** Exporter les rapports */
    public const RAPPORTS_EXPORT = 'partenaires.rapports.export';

    /** Voir les rapports */
    public const RAPPORTS_VIEW = 'partenaires.rapports.view';

    /**
     * Modules de l'application et actions déclarées pour chacun.
     *
     * @var array<string, array{label: string, actions: array<string, string>}>
     */
    public const MODULES = [
        'contacts' => ['label' => 'Contacts', 'actions' => ['create' => 'partenaires.contacts.create', 'delete' => 'partenaires.contacts.delete', 'edit' => 'partenaires.contacts.edit', 'export' => 'partenaires.contacts.export', 'view' => 'partenaires.contacts.view']],
        'conventions' => ['label' => 'Conventions', 'actions' => ['create' => 'partenaires.conventions.create', 'delete' => 'partenaires.conventions.delete', 'edit' => 'partenaires.conventions.edit', 'export' => 'partenaires.conventions.export', 'view' => 'partenaires.conventions.view']],
        'documents' => ['label' => 'Documents', 'actions' => ['create' => 'partenaires.documents.create', 'delete' => 'partenaires.documents.delete', 'edit' => 'partenaires.documents.edit', 'export' => 'partenaires.documents.export', 'view' => 'partenaires.documents.view']],
        'partenaires' => ['label' => 'Partenaires', 'actions' => ['create' => 'partenaires.partenaires.create', 'delete' => 'partenaires.partenaires.delete', 'edit' => 'partenaires.partenaires.edit', 'export' => 'partenaires.partenaires.export', 'view' => 'partenaires.partenaires.view']],
        'rapports' => ['label' => 'Rapports', 'actions' => ['create' => 'partenaires.rapports.create', 'delete' => 'partenaires.rapports.delete', 'edit' => 'partenaires.rapports.edit', 'export' => 'partenaires.rapports.export', 'view' => 'partenaires.rapports.view']],
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
            'partenaires.contacts.create',
            'partenaires.contacts.delete',
            'partenaires.contacts.edit',
            'partenaires.contacts.export',
            'partenaires.contacts.view',
            'partenaires.conventions.create',
            'partenaires.conventions.delete',
            'partenaires.conventions.edit',
            'partenaires.conventions.export',
            'partenaires.conventions.view',
            'partenaires.documents.create',
            'partenaires.documents.delete',
            'partenaires.documents.edit',
            'partenaires.documents.export',
            'partenaires.documents.view',
            'partenaires.partenaires.create',
            'partenaires.partenaires.delete',
            'partenaires.partenaires.edit',
            'partenaires.partenaires.export',
            'partenaires.partenaires.view',
            'partenaires.rapports.create',
            'partenaires.rapports.delete',
            'partenaires.rapports.edit',
            'partenaires.rapports.export',
            'partenaires.rapports.view',
        ],
        'gestionnaire' => [
            'partenaires.contacts.create',
            'partenaires.contacts.edit',
            'partenaires.contacts.export',
            'partenaires.contacts.view',
            'partenaires.conventions.create',
            'partenaires.conventions.edit',
            'partenaires.conventions.export',
            'partenaires.conventions.view',
            'partenaires.documents.create',
            'partenaires.documents.edit',
            'partenaires.documents.export',
            'partenaires.documents.view',
            'partenaires.partenaires.create',
            'partenaires.partenaires.edit',
            'partenaires.partenaires.export',
            'partenaires.partenaires.view',
            'partenaires.rapports.create',
            'partenaires.rapports.edit',
            'partenaires.rapports.export',
            'partenaires.rapports.view',
        ],
        'utilisateur' => [
            'partenaires.contacts.view',
            'partenaires.conventions.view',
            'partenaires.documents.view',
            'partenaires.partenaires.view',
            'partenaires.rapports.view',
        ],
    ];

    /**
     * Comptes de test déclarés dans l'IAM pour cette application.
     *
     * @var array<int, array{email: string, username: string, name: string, roles: string[]}>
     */
    public const TEST_USERS = [
        ['email' => 'admin.partenaires@acsi.local', 'username' => 'admin.partenaires', 'name' => 'Admin Partenaires', 'roles' => ['admin']],
        ['email' => 'gestionnaire.partenaires@acsi.local', 'username' => 'gestionnaire.partenaires', 'name' => 'Gestionnaire Partenaires', 'roles' => ['gestionnaire']],
        ['email' => 'utilisateur.partenaires@acsi.local', 'username' => 'utilisateur.partenaires', 'name' => 'Utilisateur Partenaires', 'roles' => ['utilisateur']],
    ];

    /** Code complet d'une permission : Permissions::code('contacts', 'edit'). */
    public static function code(string $module, string $action): string
    {
        return 'partenaires.'.$module.'.'.$action;
    }
}
