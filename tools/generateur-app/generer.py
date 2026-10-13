#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Générateur d'intégration IAM-Local.

Produit, pour une application DÉJÀ DÉCLARÉE dans l'IAM, un squelette
d'intégration SSO prêt à brancher, dans l'une des trois piles :

    django/    Django + DRF
    react/     React + Vite (client) + revalidation côté serveur
    express/   Express (API) + client web quelconque
    laravel/   Laravel 11 : OIDC + PKCE (voie principale), SSO maison en
               option, middlewares iam.auth / iam.permission

Le code produit est une TRANSPOSITION de ce qui fonctionne déjà dans
GestionPersonnel (Django) et ControleMaintenance (React + Express).
Il n'est pas générique : il est calé sur le contrat SSO réel de
l'IAM-Local, y compris sesirrégularités. Voir `PRET_A_LIRE.md`.

Pourquoi un générateur plutôt qu'une documentation ? Parce que la
liste des permissions est le seul élément qui change d'une application à
l'autre, et qu'il est par ailleurs la source d'erreur la plus coûteuse :
une faute de frappe sur un code ne produit aucun avertissement, seulement
un 403 à l'exécution. Ici les codes viennent de la base, ils sont donc
exacts par construction.

Emploi :

    python generer.py --app gestion-personnel
    python generer.py --app controle-maintenance --piles express
    python generer.py --json description.json --app ma-app --sortie ..\\skel
    python generer.py --app partenaires --piles laravel --sortie sortie\\partenaires

Le dossier de sortie est refusé s'il existe déjà, sauf --force : on ne
écrase jamais un squelette déjà adapté à la main.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import sys
from pathlib import Path

import lire_iam
from lire_iam import ErreurLecture

ICI = Path(__file__).resolve().parent
PILES = ("django", "react", "express", "laravel")
# La pile laravel n'est générée que sur demande explicite (--piles laravel).
PILES_PAR_DEFAUT = ("django", "react", "express")
MOTIF = re.compile(r"@@([A-Z0-9_]+)@@")
# Gabarits rendus sous forme de fichier caché (point initial ajouté).
FICHIERS_CACHES = {"env.example"}


# ── Rendu des gabarits ──────────────────────────────────────────


def context(description: dict) -> dict[str, str]:
    """
    Calcule les valeurs remplaçables dans les gabarits.

    La substitution se fait par `str.replace`, pas par `.format()` ni
    `%` : les gabarits JavaScript sont saturés de `{` et de `$`, qui
    casseraient les deux autres mécanismes.
    """
    permissions = description.get("permissions") or []
    roles_locaux = description.get("roles_locaux") or {}
    roles_globaux = description.get("roles_globaux") or {}

    largeur = max((len(p["code"]) for p in permissions), default=0)

    # Bloc de constantes Python : une constante par permission.
    perms_py = "\n".join(
        f'{p["code"].upper().replace(".", "_").replace("-", "_")} = "{p["code"]}"'
        for p in permissions
    )
    # Bloc de constantes JavaScript : un objet, lu par index.
    perms_js = "\n".join(
        f"  '{p['code']}': '{p['nom']}',"
        for p in permissions
    )
    # Permissions d'un rôle, prêtes pour un commentaire de déblocage.
    perms_role = (
        "\n".join(
            "  {0}: [{1}],".format(
                role,
                ", ".join(f'"{c}"' for c in codes) or '/* aucune */',
            )
            for role, codes in sorted(roles_locaux.items())
        )
        or "  /* aucun rôle local déclaré */"
    )

    return {
        "CODE_APP": description.get("code", ""),
        "NOM_APP": description.get("nom", ""),
        "URL_APP": description.get("url", ""),
        "DESCRIPTION": description.get("description", "") or "(non renseignée)",
        "BASE_IAM": description.get("base_iam", "").rstrip("/"),
        "APP_ID": str(description.get("id", "")),
        "DATE": dt.date.today().isoformat(),
        "IAM_VERSION": "IAM-Local 1.0.0",
        "NB_PERMS": str(len(permissions)),
        "NB_ROLES": str(len(roles_locaux)),
        "PERMS_PY": perms_py,
        "PERMS_JS": perms_js,
        "PERMS_ROLE_JS": perms_role,
        "LARGEUR": " " * largeur,
        "LISTE_PERMS": "\n".join(
            f"- `{p['code']}` — {p['nom']}"
            + (f" ({p['description']})" if p.get("description") else "")
            for p in permissions
        )
        or "- (aucune permission déclarée)",
        "MATRICE_MD": _matrice_markdown(roles_locaux, roles_globaux, permissions),
        "PERMS_JSON": json.dumps(permissions, ensure_ascii=False, indent=2),
        **_contexte_laravel(description),
    }


# ── Valeurs propres à la pile laravel ───────────────────────────


def _php(texte: str) -> str:
    """Chaîne PHP entre apostrophes."""
    return "'" + str(texte).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _libelle_module(module: str, permissions: list[dict], code_app: str) -> str:
    """
    Libellé lisible d'un module, tiré du nom de sa permission « view »
    (« Voir les offres d'emploi » → « Offres d'emploi »).
    """
    vue = next((p for p in permissions if p["code"] == f"{code_app}.{module}.view"), None)
    if vue:
        nom = re.sub(r"^(voir|consulter)\s+", "", vue["nom"], flags=re.IGNORECASE)
        nom = re.sub(r"^(les|la|le|l')\s*", "", nom, flags=re.IGNORECASE)
        if nom:
            return nom[0].upper() + nom[1:]
    return module.replace("-", " ").capitalize()


def _modules(permissions: list[dict], code_app: str) -> dict[str, dict[str, str]]:
    """{module: {action: code}} pour les codes de forme <app>.<module>.<action>."""
    modules: dict[str, dict[str, str]] = {}
    for p in permissions:
        morceaux = p["code"].split(".")
        if len(morceaux) == 3 and morceaux[0] == code_app:
            modules.setdefault(morceaux[1], {})[morceaux[2]] = p["code"]
    return modules


def _contexte_laravel(description: dict) -> dict[str, str]:
    code_app = description.get("code", "")
    permissions = description.get("permissions") or []
    url_app = (description.get("url") or "").rstrip("/")
    client = description.get("client_oidc") or {}
    port = re.search(r":(\d+)(?:/|$)", url_app)

    consts = []
    for p in permissions:
        reste = p["code"][len(code_app) + 1:] if p["code"].startswith(code_app + ".") else p["code"]
        nom = re.sub(r"[^A-Za-z0-9]+", "_", reste).strip("_").upper()
        consts.append(f"    /** {p['nom']} */\n    public const {nom} = {_php(p['code'])};")

    modules = _modules(permissions, code_app)
    lignes_modules = []
    for module, actions in modules.items():
        acts = ", ".join(f"{_php(a)} => {_php(c)}" for a, c in actions.items())
        lignes_modules.append(
            f"        {_php(module)} => ['label' => {_php(_libelle_module(module, permissions, code_app))}, "
            f"'actions' => [{acts}]],"
        )

    matrice = description.get("roles_locaux") or {}
    lignes_matrice = []
    for role, codes in sorted(matrice.items()):
        corps = "".join(f"\n            {_php(c)}," for c in sorted(codes))
        lignes_matrice.append(f"        {_php(role)} => [{corps}\n        ],")

    lignes_comptes = [
        f"        ['email' => {_php(c['email'])}, 'username' => {_php(c['username'])}, "
        f"'name' => {_php(c['nom'])}, 'roles' => [{', '.join(_php(r) for r in c['roles'])}]],"
        for c in description.get("comptes_test") or []
    ]

    routes = []
    gabarit_route = {
        "view":   [("get", "'/'", "index")],
        "create": [("get", "'/create'", "create"), ("post", "'/'", "store")],
        "export": [("get", "'/export'", "export")],
        "edit":   [("get", "'/{id}/edit'", "edit"), ("put", "'/{id}'", "update")],
        "delete": [("delete", "'/{id}'", "destroy")],
    }
    for module, actions in modules.items():
        routes.append(f"    // {_libelle_module(module, permissions, code_app)}")
        routes.append(f"    Route::prefix({_php(module)})->name({_php(module + '.')})->controller(ModuleController::class)->group(function () {{")
        for action in ("view", "create", "export", "edit", "delete"):
            if action not in actions:
                continue
            for verbe, uri, methode in gabarit_route[action]:
                routes.append(
                    f"        Route::{verbe}({uri}, {_php(methode)})->name({_php(methode)})"
                    f"->defaults('module', {_php(module)})"
                    f"->middleware({_php('iam.permission:' + actions[action])});"
                )
        routes.append("    });")
        routes.append("")

    # Matrice compacte : une ligne par module, une colonne par rôle.
    roles_tries = sorted(matrice)
    compacte = ["| Module | " + " | ".join(f"`{r}`" for r in roles_tries) + " |",
                "|---|" + "---|" * len(roles_tries)]
    for module, actions in modules.items():
        cellules = []
        for role in roles_tries:
            acc = [a for a, c in actions.items() if c in matrice.get(role, [])]
            cellules.append(", ".join(acc) or "—")
        compacte.append(f"| {_libelle_module(module, permissions, code_app)} | " + " | ".join(cellules) + " |")

    return {
        "MATRICE_COMPACTE_MD": "\n".join(compacte) if roles_tries else "_Aucun rôle local déclaré._",
        "CLIENT_ID": client.get("client_id") or f"iam-laravel-{code_app}",
        "PORT_APP": port.group(1) if port else "8000",
        "CODE_APP_SQL": re.sub(r"[^a-z0-9]+", "_", code_app.lower()),
        "COULEUR_APP": description.get("couleur") or "#1a237e",
        "PKCE": "obligatoire" if client.get("pkce_required") else "facultatif (à activer !)",
        "REDIRECT_URIS": ", ".join(client.get("redirect_uris") or []) or "(aucun client OIDC déclaré)",
        "PHP_PERM_CONSTS": "\n\n".join(consts) or "    // (aucune permission déclarée)",
        "PHP_MODULES": "\n".join(lignes_modules) or "        // (aucun module)",
        "PHP_MATRIX": "\n".join(lignes_matrice) or "        // (aucun rôle local)",
        "PHP_TEST_USERS": "\n".join(lignes_comptes) or "        // (aucun compte de test)",
        "PHP_ROUTES": "\n".join(routes).rstrip() or "    // (aucune permission déclarée : aucune route de module)",
    }


def _matrice_markdown(locaux: dict, globaux: dict, permissions: list[dict]) -> str:
    """Tableau Markdown des rôles × permissions, pour le README généré."""
    codes = [p["code"] for p in permissions]
    if not codes:
        return "_Aucune permission déclarée pour cette application._"

    court = {c: c.split(".")[-1][:4] for c in codes}
    lignes = ["| Rôle | " + " | ".join(f"`{c}`<br>{court[c]}" for c in codes) + " |"]
    lignes.append("|" + "---|" * (len(codes) + 1))
    for titre, matrice in (("Rôle local", locaux), ("Rôle global", globaux)):
        for role, _codes in sorted(matrice.items()):
            cases = " | ".join("x" if c in _codes else "·" for c in codes)
            lignes.append(f"| *{titre}* `{role}` | {cases} |")
    return "\n".join(lignes)


def rendre(gabarit: str, valeurs: dict[str, str]) -> str:
    """Remplace les @@CLE@@ ; signale les clés inconnues."""
    def _sub(m):
        cle = m.group(1)
        if cle not in valeurs:
            raise ErreurLecture(f"Clé @@{cle}@@ absente du contexte de génération")
        return valeurs[cle]

    return MOTIF.sub(_sub, gabarit)


# ── Génération ──────────────────────────────────────────────────


def generer_pile(pile: str, description: dict, sortie: Path, valeurs: dict) -> list[Path]:
    """Copie et rend tous les gabarits d'une pile. Renvoie les fichiers écrits."""
    source = ICI / "piles" / pile
    if not source.is_dir():
        raise ErreurLecture(f"Aucune pile « {pile} » dans {source}")

    cible = sortie / pile
    cible.mkdir(parents=True, exist_ok=True)

    ecrits = []
    for gabarit in sorted(source.rglob("*.gabarit")):
        relatif = gabarit.relative_to(source).with_suffix("")
        # Fichiers cachés : le gabarit porte un nom visible (« env.example »)
        # que certains outils de copie refusent sous sa forme « .env… ».
        if relatif.name in FICHIERS_CACHES:
            relatif = relatif.with_name("." + relatif.name)
        destination = cible / relatif
        destination.parent.mkdir(parents=True, exist_ok=True)
        contenu = rendre(gabarit.read_text(encoding="utf-8"), valeurs)
        destination.write_text(contenu, encoding="utf-8", newline="\n")
        ecrits.append(destination)
    return ecrits


def generer_commun(description: dict, sortie: Path, valeurs: dict) -> list[Path]:
    """Fichiers indépendants de la pile : README, catalogue JSON, matrice."""
    source = ICI / "piles" / "commun"
    cible = sortie
    cible.mkdir(parents=True, exist_ok=True)

    ecrits = []
    for gabarit in sorted(source.rglob("*.gabarit")):
        relatif = gabarit.relative_to(source).with_suffix("")
        destination = cible / relatif
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            rendre(gabarit.read_text(encoding="utf-8"), valeurs),
            encoding="utf-8",
            newline="\n",
        )
        ecrits.append(destination)
    return ecrits


def verifier_coherences(sortie: Path, description: dict) -> list[str]:
    """
    Compare les codes réellement cités dans le squelette aux codes
    déclarés dans l'IAM.

    Détecte le symétrique de la faute de frappe : un code utilisé dans
    le code mais jamais déclaré dans l'IAM. Il ne fonctionnera jamais,
    et sans cette vérification l'erreur n'apparaît qu'en production.
    """
    declares = {p["code"] for p in description.get("permissions") or []}
    if not declares:
        return []

    motif = re.compile(r"[\"']([\w-]+\.[\w-]+(?:\.[\w-]+)*)[\"']")
    inconnus: dict[str, set[str]] = {}

    for fichier in sortie.rglob("*"):
        if fichier.suffix not in {".py", ".js", ".jsx", ".php"}:
            continue
        for code in motif.findall(fichier.read_text(encoding="utf-8", errors="replace")):
            # Se limiter aux codes qui ressemblent à ceux de cette app.
            if "." in code and code not in declares and code.split(".")[0] in {
                c.split(".")[0] for c in declares
            }:
                inconnus.setdefault(code, set()).add(str(fichier.name))

    return [
        f"code « {code} » utilisé dans {', '.join(sorted(fichiers))} "
        f"mais non déclaré dans l'IAM"
        for code, fichiers in sorted(inconnus.items())
    ]


# ── Ligne de commande ───────────────────────────────────────────


def analyser_arguments() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Génère un squelette d'intégration SSO depuis une app IAM déclarée.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--app", help="Code applicatif dans l'IAM (ex : gestion-personnel)")
    p.add_argument("--json", help="Export JSON de description, à la place de la base")
    p.add_argument(
        "--piles",
        default=",".join(PILES_PAR_DEFAUT),
        help=f"Piles à générer, séparées par des virgules ({', '.join(PILES)})",
    )
    p.add_argument("--sortie", help="Dossier de sortie (défaut : ./generation-<app>)")
    p.add_argument("--force", action="store_true", help="Écrase un dossier existant")
    return p.parse_args()


def main(argv: list[str] | None = None) -> int:
    args = analyser_arguments()

    piles = [p.strip() for p in args.piles.split(",") if p.strip()]
    inconnues = set(piles) - set(PILES)
    if inconnues:
        print(f"Pile inconnue : {', '.join(sorted(inconnues))}", file=sys.stderr)
        print(f"Piles disponibles : {', '.join(PILES)}", file=sys.stderr)
        return 2

    try:
        description, _config = lire_iam.charger(args.json or args.app or "", args.app)
    except ErreurLecture as exc:
        print(f"ERREUR : {exc}", file=sys.stderr)
        return 1

    valeurs = context(description)
    sortie = Path(args.sortie) if args.sortie else Path.cwd() / f"generation-{description['code']}"
    if sortie.exists():
        if not args.force:
            print(
                f"ERREUR : {sortie} existe déjà.\n"
                "Le squelette est-il adapté ? Utilisez --sortie ou --force.",
                file=sys.stderr,
            )
            return 1
        shutil.rmtree(sortie)
    sortie.mkdir(parents=True)

    ecrits = generer_commun(description, sortie, valeurs)
    for pile in piles:
        ecrits += generer_pile(pile, description, sortie, valeurs)

    # ── Compte rendu ──
    print(f"Application : {description['nom']} ({description['code']})")
    print(f"IAM         : {valeurs['BASE_IAM']}")
    print(f"Permissions : {valeurs['NB_PERMS']}")
    print(f"Rôles locaux: {valeurs['NB_ROLES']}")
    print(f"            : {', '.join(sorted(description.get('roles_locaux') or {})) or 'aucun'}")
    print(f"\n{len(ecrits)} fichiers écrits dans {sortie}\n")
    for pile in piles:
        fichiers = sorted((sortie / pile).rglob("*"))
        fichiers = [f for f in fichiers if f.is_file()]
        print(f"  {pile}/  ({len(fichiers)} fichiers)")
        for f in fichiers:
            print(f"    {f.relative_to(sortie / pile)}")

    alertes = verifier_coherences(sortie, description)
    if alertes:
        print("\nAnomalies :")
        for alerte in alertes:
            print(f"  ! {alerte}")
        return 3

    if not description.get("permissions"):
        print(
            "\nATTENTION : cette application n'a aucune permission déclarée.\n"
            "           Le squelette fonctionne, mais tout sera refusé (403)."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())