"""
Lecture de la description d'une application dans l'IAM-Local.

L'IAM est la seule source de vérité sur ce qu'une application peut faire.
Plutôt que de recopier la liste des permissions dans un fichier de
configuration — source de désynchronisation garantie — ce module la lit
là où elle est déclarée.

Trois entrées possibles, dans cet ordre de préférence :

  1. la base `iam_local` (par défaut) ;
  2. un export JSON, pour générer hors ligne ou sur une machine sans
     accès à la base ;
  3. la configuration PHP, pour les identifiants.

Aucun secret n'est écrit dans les fichiers générés : la connexion à la
base n'est lue que pour consulter, et le code produit ne contient que
l'adresse publique de l'IAM.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# Racine de l'IAM : deux niveaux au-dessus de tools/generateur-app/,
# quel que soit l'emplacement de l'installation (auparavant figée sur
# C:\wamp64\www\IAM-Local).
RACINE_IAM = Path(__file__).resolve().parents[2]


class ErreurLecture(Exception):
    """La description de l'application n'a pas pu être obtenue."""


# ── Configuration PHP ───────────────────────────────────────────


def lire_config_php(chemin: Path | None = None) -> dict[str, str]:
    """
    Extrait les constantes de config/config.php.

    Expression régulière plutôt qu'un vrai analyseur PHP : le fichier
    n'est pas du code arbitraire mais une suite de `define('CLE', 'VAL')`,
    et éviter d'appeler PHP rend l'outil utilisable sans interpréteur.
    """
    fichier = chemin or (RACINE_IAM / "config" / "config.php")
    if not fichier.exists():
        raise ErreurLecture(f"Fichier introuvable : {fichier}")

    source = fichier.read_text(encoding="utf-8", errors="replace")
    # On tolère les deux écritures de PHP : simples et doubles quotes.
    motif = re.compile(
        r"""define\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*['"]([^'"]*)['"]\s*\)""",
        re.IGNORECASE,
    )
    valeurs = {nom: valeur for nom, valeur in motif.findall(source)}

    if "IAM_BASE_URL" not in valeurs:
        raise ErreurLecture(f"IAM_BASE_URL absent de {fichier}")
    return valeurs


# ── Accès base ──────────────────────────────────────────────────


def _connecter(config: dict[str, str]):
    """
    Connexion à `iam_local`.

    PyMySQL est utilisé s'il est présent ; sinon on échoue avec un
    message qui indique la marche à suivre, plutôt qu'une
    ImportError illisible.
    """
    try:
        import pymysql
    except ImportError as exc:  # pragma: no cover - dépend de l'environnement
        raise ErreurLecture(
            "PyMySQL est requis pour lire la base.\n"
            "  pip install pymysql\n"
            "ou bien : python generer.py --json description.json ..."
        ) from exc

    return pymysql.connect(
        host=config.get("DB_HOST", "localhost"),
        port=int(config.get("DB_PORT", "3306")),
        user=config.get("DB_USER", "root"),
        password=config.get("DB_PASS", ""),
        database=config.get("DB_NAME", "iam_local"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )


def _valeurs_par_index(elements: list[dict], cle: str) -> dict[int, str]:
    """
    Regroupe des enregistrements.indexés par `cle`.

    `elements` est plat (une ligne par permission) ; on en sort une
    table id -> valeur, pour ensuite reconstruire une matrice par rôle.
    """
    table: dict[int, str] = {}
    for element in elements:
        code = element.get(cle)
        if code:
            table[element["id"]] = str(code)
    return table


def _matrice_roles(
    curseur, app_id: int, prefixe: str
) -> dict[str, list[str]]:
    """
    Construit {code_rôle: [permissions]} pour une application.

    `prefixe` distingue les rôles globaux (`NULL`) des rôles locaux.
    Les deux sont utiles : un rôle global comme `admin` porte des droits
    sur toutes les applications, un rôle local n'existe que pour celle-ci.
    """
    if prefixe == "globaux":
        curseur.execute(
            "SELECT r.id, r.code FROM roles r "
            "WHERE r.application_id IS NULL AND r.is_system = 0 "
            "ORDER BY r.code"
        )
    else:
        curseur.execute(
            "SELECT r.id, r.code FROM roles r "
            "WHERE r.application_id = %s AND r.is_system = 0 "
            "ORDER BY r.code",
            (app_id,),
        )
    roles = {row["id"]: row["code"] for row in curseur.fetchall()}
    if not roles:
        return {}

    ids = tuple(roles)
    curseur.execute(
        # Parenthèses indispensables : « IN %s,%s » est une erreur de
        # syntaxe SQL (défaut corrigé, le générateur échouait dès qu'une
        # application avait des rôles locaux).
        "SELECT role_id, permission_id FROM role_permissions WHERE role_id IN ("
        + ",".join(["%s"] * len(ids))
        + ")",
        ids,
    )
    liaisons = curseur.fetchall()

    curseur.execute("SELECT id, code FROM permissions WHERE application_id = %s", (app_id,))
    par_permission = _valeurs_par_index(curseur.fetchall(), "code")

    matrice: dict[str, list[str]] = {code: [] for code in roles.values()}
    for ligne in liaisons:
        code_role = roles.get(ligne["role_id"])
        code_perm = par_permission.get(ligne["permission_id"])
        if code_role and code_perm and code_perm not in matrice[code_role]:
            matrice[code_role].append(code_perm)
    return matrice


def lire_de_la_base(code_app: str, config: dict[str, str]) -> dict:
    """Description complète d'une application, lue dans `iam_local`."""
    connexion = _connecter(config)
    try:
        with connexion.cursor() as curseur:
            curseur.execute(
                "SELECT id, code, name, description, url, color, active, sso_prompt, "
                "redirect_uri FROM applications WHERE code = %s",
                (code_app,),
            )
            app = curseur.fetchone()
            if not app:
                curseur.execute("SELECT code FROM applications ORDER BY code")
                connues = ", ".join(r["code"] for r in curseur.fetchall())
                raise ErreurLecture(
                    f"Application « {code_app} » inconnue.\n"
                    f"Applications déclarées : {connues or 'aucune'}"
                )

            curseur.execute(
                "SELECT id, code, name, description FROM permissions "
                "WHERE application_id = %s ORDER BY code",
                (app["id"],),
            )
            permissions = curseur.fetchall()

            return {
                **_client_oidc(curseur, app["id"]),
                "couleur": app.get("color") or "",
                "comptes_test": _comptes(curseur, app["id"]),
                "code": app["code"],
                "nom": app["name"],
                "description": app.get("description") or "",
                "url": app.get("url") or "",
                "active": bool(app.get("active")),
                "sso_prompt": bool(app.get("sso_prompt")),
                "redirect_uri": app.get("redirect_uri") or "",
                "id": app["id"],
                "base_iam": config.get("IAM_BASE_URL", "").rstrip("/"),
                "permissions": [
                    {"code": p["code"], "nom": p["name"], "description": p.get("description") or ""}
                    for p in permissions
                ],
                "roles_locaux": _matrice_roles(curseur, app["id"], "locaux"),
                "roles_globaux": _matrice_roles(curseur, app["id"], "globaux"),
            }
    finally:
        connexion.close()


def _client_oidc(curseur, app_id: int) -> dict:
    """
    Client OAuth/OIDC lié à l'application (oauth_clients), s'il existe.

    Seuls les éléments PUBLICS sont lus : client_id, URI, scopes, PKCE.
    Le secret n'est jamais lu (il est d'ailleurs stocké haché).
    """
    curseur.execute(
        "SELECT client_id, client_type, redirect_uris, post_logout_uris, scopes, "
        "pkce_required FROM oauth_clients WHERE application_id = %s "
        "ORDER BY is_active DESC, id LIMIT 1",
        (app_id,),
    )
    client = curseur.fetchone()
    if not client:
        return {"client_oidc": None}

    def _liste(valeur):
        try:
            donnee = json.loads(valeur or "[]")
        except (TypeError, ValueError):
            donnee = str(valeur or "").split()
        return donnee if isinstance(donnee, list) else []

    return {
        "client_oidc": {
            "client_id": client["client_id"],
            "client_type": client["client_type"],
            "redirect_uris": _liste(client["redirect_uris"]),
            "post_logout_uris": _liste(client["post_logout_uris"]),
            "scopes": _liste(client["scopes"]),
            "pkce_required": bool(client["pkce_required"]),
        }
    }


def _comptes(curseur, app_id: int) -> list[dict]:
    """
    Comptes ayant au moins un rôle sur l'application, avec leurs rôles.

    Limité aux comptes de test (domaine acsi.local) : le squelette
    généré ne doit pas embarquer l'annuaire réel.
    """
    curseur.execute(
        "SELECT u.email, u.username, u.first_name, u.last_name, r.code AS role "
        "FROM user_roles ur "
        "JOIN users u ON u.id = ur.user_id "
        "JOIN roles r ON r.id = ur.role_id "
        "WHERE ur.application_id = %s AND u.email LIKE %s "
        "ORDER BY u.email, r.code",
        (app_id, "%@acsi.local"),
    )
    comptes: dict[str, dict] = {}
    for ligne in curseur.fetchall():
        compte = comptes.setdefault(ligne["email"], {
            "email": ligne["email"],
            "username": ligne["username"],
            "nom": f"{ligne['first_name']} {ligne['last_name']}".strip(),
            "roles": [],
        })
        compte["roles"].append(ligne["role"])
    return list(comptes.values())


# ── Fichier JSON ────────────────────────────────────────────────


def lire_de_json(chemin: Path, code_app: str | None = None) -> dict:
    """
    Description au format JSON.

    Utile pour générer sans base (démo, CI, machine de développement
    dépourvue de MySQL). Un fichier peut décrire plusieurs applications ;
    on choisit alors celle dont le code est demandé.
    """
    try:
        brut = json.loads(chemin.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ErreurLecture(f"JSON illisible dans {chemin} : {exc}") from None

    applications = brut["applications"] if isinstance(brut, dict) else brut
    if code_app:
        trouvee = next((a for a in applications if a.get("code") == code_app), None)
        if not trouvee:
            codes = ", ".join(a.get("code", "?") for a in applications)
            raise ErreurLecture(f"« {code_app} » absent de {chemin}. Disponibles : {codes}")
        return trouvee
    if len(applications) == 1:
        return applications[0]
    raise ErreurLecture("Plusieurs applications décrites : précisez --app.")


# ── Fabrique ────────────────────────────────────────────────────


def charger(source: str, code_app: str | None) -> tuple[dict, dict]:
    """
    Point d'entrée unique : renvoie (description, configuration).

    `source` vaut soit un chemin JSON existant, soit le code applicatif
    à lire dans la base.
    """
    config = lire_config_php()

    if source and Path(source).exists() and source.lower().endswith(".json"):
        return lire_de_json(Path(source), code_app), config

    code = code_app or source
    if not code:
        raise ErreurLecture("Indiquez le code applicatif (--app) ou un export JSON (--json).")
    return lire_de_la_base(code, config), config