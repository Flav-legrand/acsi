<?php
/**
 * IAM-Local — Filtre d'interface par permissions IAM (bibliothèque autonome)
 *
 * À inclure dans les applications externes (Gestion des Salaires, Gestion des
 * Présences…) APRÈS iam_client.php. Ne dépend d'aucun autre fichier du projet.
 *
 * Principe « cacher ET bloquer » :
 *   - peut()          : faut-il afficher ce lien / bouton ?
 *   - iam_require()   : garde de page — sinon 403 propre
 *   - iam_menu_item() : affiche un <li> de menu seulement si permis
 *
 * Sources de permissions reconnues (la première renseignée gagne) :
 *   1. $_SESSION['iam_permissions']   (client SSO natif iam_client.php)
 *   2. $_SESSION['user']['permissions'] (GestionPresnceAdenIAM / sso-login-native)
 *   3. Rôles mappés en rôle applicatif local ($_SESSION['user_role']) —
 *      compatibilité avec les anciennes sessions : 'admin' => toutes perms.
 *
 * Un utilisateur SANS aucune information de permission est traité en
 * consultation seule : les pages de lecture restent accessibles, toute
 * écriture est refusée. L'inverse accorderait l'app à des sessions
 * incomplètes.
 */

if (!defined('IAM_GATE_LOADED')) {
    define('IAM_GATE_LOADED', 1);

    /** Jokers acceptés dans la liste des permissions. */
    $GLOBALS['IAM_GATE_JOKERS'] = ['*', 'admin'];

    /**
     * Liste plate des permissions de l'utilisateur courant.
     *
     * @return string[]
     */
    function iam_gate_permissions(): array
    {
        static $cache = null;
        if ($cache !== null) return $cache;

        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }

        $perms = [];

        // 1. Session natif IAM-Local (iam_client.php)
        if (!empty($_SESSION['iam_permissions']) && is_array($_SESSION['iam_permissions'])) {
            $perms = array_merge($perms, $_SESSION['iam_permissions']);
        }

        // 2. Format GestionPresnceAdenIAM ($_SESSION['user']['permissions'])
        if (!empty($_SESSION['user']['permissions']) && is_array($_SESSION['user']['permissions'])) {
            $perms = array_merge($perms, $_SESSION['user']['permissions']);
        }

        // 3. Rôles IAM bruts (codes) : certains clients ne stockent que eux
        foreach (($_SESSION['iam_roles'] ?? []) as $r) {
            $perms[] = is_string($r) ? $r : (string) ($r['code'] ?? '');
        }
        if (!empty($_SESSION['user']['roles']) && is_array($_SESSION['user']['roles'])) {
            foreach ($_SESSION['user']['roles'] as $r) {
                $perms[] = is_string($r) ? $r : (string) ($r['code'] ?? '');
            }
        }

        // 4. Admin global IAM => tout
        $isGlobalAdmin = !empty($_SESSION['user']['is_global_admin'])
            || !empty($_SESSION['sso_user']['is_global_admin']);
        if ($isGlobalAdmin) {
            $perms[] = '*';
        }

        // Normalisation : chaînes non vides, dédoublonnées
        $perms = array_values(array_unique(array_filter(array_map('strval', $perms), fn($p) => $p !== '')));

        // 5. Rôle applicatif local hérité des anciennes sessions
        //    (aucune permission IAM reçue : on retombe sur user_role)
        if (empty($perms) || in_array('*', $perms, true)) {
            $role = (string) ($_SESSION['user_role'] ?? $_SESSION['arole'] ?? '');
            if ($role === 'admin') {
                $perms[] = '*';
            }
        }

        return $cache = $perms;
    }

    /**
     * L'utilisateur courant possède-t-il AU MOINS UNE de ces permissions ?
     * Accepte plusieurs codes (ex : peut('salary.view','salary.manage')).
     *
     * @param string ...$codes
     * @return bool
     */
    function peut(string ...$codes): bool
    {
        if (!$codes) return false;
        $perms = iam_gate_permissions();
        foreach ($GLOBALS['IAM_GATE_JOKERS'] as $j) {
            if (in_array($j, $perms, true)) return true;
        }
        foreach ($codes as $c) {
            if (in_array($c, $perms, true)) return true;
        }
        return false;
    }

    /** Alias court explicite. */
    function iam_peut(string ...$codes): bool
    {
        return peut(...$codes);
    }

    /**
     * Garde de page : termine la requête par un 403 lisible si refusé.
     *   iam_require('salary.manage')              -> page 403 HTML
     *   iam_require('salary.manage', 'avances.php')-> redirection avec ?error=
     */
    function iam_require(string $perm, string $redirectOnDeny = ''): void
    {
        if (peut($perm)) return;

        $redirect = $redirectOnDeny;

        if ($redirect !== '') {
            header('Location: ' . $redirect . (strpos($redirect, '?') === false ? '?' : '&') . 'error=' . rawurlencode('Accès refusé : droit insuffisant.'));
            exit;
        }
        http_response_code(403);
        echo '<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>403 — Accès refusé</title>'
           . '<style>body{font-family:system-ui,sans-serif;background:#f1f5f9;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}'
           . '.box{background:#fff;padding:40px 48px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.08);text-align:center;max-width:420px}'
           . 'h1{color:#dc2626;margin:0 0 8px;font-size:42px}p{color:#475569;margin:0 0 20px}'
           . 'a{color:#2563eb;text-decoration:none;font-weight:600}</style></head><body><div class="box">'
           . '<h1>403</h1><p>Accès refusé : votre rôle ne permet pas d\'accéder à cette page.<br>Contactez l\'administrateur IAM si vous pensez avoir besoin de ce droit.</p>'
           . '<a href="javascript:history.back()">&larr; Retour</a></div></body></html>';
        exit;
    }

    /**
     * Affiche un <li> de menu si l'utilisateur possède la permission.
     * Usage : <?php iam_menu_item('salary.manage', '<li>...</li>'); ?>
     * ou avec callback : iam_menu_item('perm', function() { echo '...'; });
     */
    function iam_menu_item(string $perm, $content): void
    {
        if (!peut($perm)) return;
        if (is_callable($content)) {
            $content();
        } else {
            echo $content;
        }
    }
}
