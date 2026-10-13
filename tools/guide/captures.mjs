// IAM-Local — Production automatique des captures du guide (docs/captures/).
//
// Usage (Node >= 22, Chrome ou Edge installé) :
//   IAM_GUIDE_BASE=http://localhost/IAM-Guide-Demo \
//   IAM_GUIDE_ROOT=C:/wamp64/www/IAM-Guide-Demo \
//   IAM_GUIDE_PASSWORD_FILE=/chemin/hors-depot/admin_pw.txt \
//   node tools/guide/captures.mjs [numéro…]
//
// À lancer sur une instance de DÉMONSTRATION (install.php avec données de
// démo + sql/seed-app-partenaires.sql) : les captures ne doivent montrer
// aucune donnée réelle. Le mot de passe (celui de l'admin, repris par les
// comptes de test) est lu dans un fichier hors dépôt, jamais en argument.
// IAM_GUIDE_ROOT sert à générer les codes MFA (iam_generate_otp) via PHP.
//
// Le plan détaillé (écran, actions, zones floutées, légende) est dans
// docs/captures/README.md ; il correspond à la liste STEPS ci-dessous.

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Browser } from './cdp.mjs';

const BASE = (process.env.IAM_GUIDE_BASE ?? 'http://localhost/IAM-Guide-Demo').replace(/\/$/, '');
const ROOT = process.env.IAM_GUIDE_ROOT ?? 'C:/wamp64/www/IAM-Guide-Demo';
const PASSWORD = readFileSync(process.env.IAM_GUIDE_PASSWORD_FILE ?? '', 'utf8').trim();
const OUT = join(dirname(fileURLToPath(import.meta.url)), '../../docs/captures');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const ACCOUNTS = {
  admin: 'admin@acsi.local',                        // administrateur IAM (exempté de MFA)
  user: 'gestionnaire.partenaires@acsi.local',      // rôle gestionnaire sur partenaires
  norole: 'gestionnaire.rh@aden.dz',                // aucun rôle sur partenaires
  locked: 'utilisateur.stages-emplois@acsi.local',  // servira à la démonstration du blocage
};

// Requête d'autorisation OIDC du client Laravel « partenaires » (PKCE S256)
const AUTHORIZE = `${BASE}/oauth.php?` + new URLSearchParams({
  response_type: 'code', client_id: 'iam-laravel-partenaires', redirect_uri: 'http://localhost:8001/callback',
  scope: 'openid profile email roles offline_access', state: 'guide',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
});

const show = (id) => `document.getElementById(${JSON.stringify(id)}).style.display='block'`;
const fill = (pairs) => Object.entries(pairs)
  .map(([sel, v]) => `(document.querySelector(${JSON.stringify(sel)})||{}).value=${JSON.stringify(v)};`).join('');
const scrollTo = (sel) => `document.querySelector(${JSON.stringify(sel)})?.scrollIntoView({block:'start'});window.scrollBy(0,-20)`;
const firstMatching = (sel, text) =>
  `[...document.querySelectorAll(${JSON.stringify(sel)})].find(e=>e.innerText.includes(${JSON.stringify(text)}))`;

// as : compte connecté (null = déconnecté) ; run : actions avant capture ;
// blur : sélecteurs CSS floutés (mots de passe, secrets) ; w : largeur
// (1440 par défaut, plus large quand la page se tasse à 1440 px).
const STEPS = [
  { n: '01', file: '01-login.png', as: null, url: '/login.php' },
  { n: '02', file: '02-login-erreur.png', as: null, url: '/login.php',
    run: async (b) => b.evalAndWait(fill({ '#identifier': ACCOUNTS.user, '#password': 'mauvais-mot-de-passe' }) + 'document.querySelector("form").submit()'),
    blur: ['input[type=password]'] },
  { n: '03', file: '03-mfa-saisie.png', as: 'user-before-mfa', url: null, blur: ['.mono'] }, // code OTP du mode démo
  { n: '04', file: '04-compte-verrouille.png', as: null, url: '/login.php',
    run: async (b) => {
      for (let i = 0; i < 5; i++) {
        await b.goto(`${BASE}/login.php`);
        await b.evalAndWait(fill({ '#identifier': ACCOUNTS.locked, '#password': `faux-${i}` }) + 'document.querySelector("form").submit()');
      }
    }, blur: ['input[type=password]'] },
  { n: '05', file: '05-portail.png', as: 'user', url: '/portal.php' },
  { n: '06', file: '06-profil.png', as: 'user', url: '/profile.php' },
  { n: '07', file: '07-profil-mot-de-passe.png', as: 'user', url: '/profile.php',
    run: async (b) => {
      await b.evalAndWait(fill({ '[name=current_password]': PASSWORD, '[name=new_password]': 'abc', '[name=confirm_password]': 'abc' })
        + 'document.querySelector("[name=new_password]").form.submit()');
      await b.eval(scrollTo('[name=new_password]') + ';' + `document.querySelector('.alert')?.scrollIntoView({block:'start'})`);
    }, blur: ['input[type=password]'] },
  { n: '08', file: '08-portail-administrateur.png', as: 'admin', url: '/portal.php' },
  { n: '09', file: '09-admin-tableau-de-bord.png', as: 'admin', url: '/admin/index.php' },
  { n: '10', file: '10-admin-users-liste.png', as: 'admin', url: '/admin/users.php' },
  { n: '11', file: '11-admin-users-create.png', as: 'admin', url: '/admin/users.php',
    run: async (b) => b.eval(show('createModal') + ';' + fill({
      '#createModal [name=first_name]': 'Awa', '#createModal [name=last_name]': 'Diallo',
      '#createModal [name=email]': 'awa.diallo@acsi.local', '#createModal [name=username]': 'adiallo',
      '#createModal [name=matricule]': 'AGT-0042', '#createModal [name=password]': 'Exemple!2026',
      '#createModal [name=fonction]': 'Chargée de partenariats',
    })), blur: ['input[type=password]', '#createModal [name=password]'] },
  { n: '12', file: '12-admin-users-edit.png', as: 'admin', url: '/admin/users.php?action=edit&id=4' },
  { n: '13', file: '13-admin-users-reset-mdp.png', as: 'admin', url: '/admin/users.php',
    run: async (b) => b.eval(`(${firstMatching('button', 'Mot de passe')}).click()`), blur: ['input[type=password]'] },
  { n: '14', file: '14-admin-users-import-csv.png', as: 'admin', url: '/admin/users.php', run: async (b) => b.eval(show('importModal')) },
  { n: '15', file: '15-admin-applications.png', as: 'admin', url: '/admin/apps.php' },
  { n: '16', file: '16-admin-applications-create.png', as: 'admin', url: '/admin/apps.php',
    run: async (b) => b.eval(`(${firstMatching('h2,h3', 'Informations de l')})?.scrollIntoView({block:'start'})`) },
  { n: '17', file: '17-admin-applications-integration-sso.png', as: 'admin', url: '/admin/apps.php',
    run: async (b) => b.eval(`(${firstMatching('button', 'Intégration SSO')}).click()`) },
  { n: '18', file: '18-admin-oidc-liste.png', as: 'admin', url: '/admin/oidc_apps.php' },
  { n: '19', file: '19-admin-oidc-wizard-plateforme.png', as: 'admin', url: '/admin/oidc_wizard.php' },
  { n: '20', file: '20-admin-oidc-wizard-configuration.png', as: 'admin', url: '/admin/oidc_wizard.php',
    run: async (b) => b.eval(fill({ '[name=name]': 'Gestion des congés', '[name=slug]': 'conges', '[name=base_url]': 'http://localhost:8003' })
      + `document.querySelector('[data-step="0"] [data-next]').click()`) },
  { n: '21', file: '21-admin-oidc-detail.png', as: 'admin', url: '/admin/oidc_apps.php?view=1',
    blur: ['[data-secret]', '.secret', 'code.secret', 'input[name*=secret]'] },
  { n: '22', file: '22-admin-roles.png', as: 'admin', url: '/admin/roles.php' },
  { n: '23', file: '23-admin-roles-permissions.png', as: 'admin', url: '/admin/roles.php',
    run: async (b) => b.eval(`(${firstMatching('button', 'Permissions')}).click()`) },
  { n: '24', file: '24-admin-applications-permissions.png', as: 'admin', url: '/admin/apps.php',
    run: async (b) => b.eval(`(${firstMatching('button', 'Permissions (')}).click()`) },
  { n: '25', file: '25-admin-applications-acces.png', as: 'admin', url: '/admin/apps.php',
    run: async (b) => b.eval(`(${firstMatching('button', 'Accès utilisateurs')}).click()`) },
  { n: '26', file: '26-admin-organisations.png', as: 'admin', url: '/admin/organizations.php' },
  { n: '27', file: '27-admin-groupes.png', as: 'admin', url: '/admin/groups.php', run: async (b) => b.eval(show('groupModal')) },
  { n: '28', file: '28-admin-audit.png', as: 'admin', url: '/admin/audit.php' },
  { n: '29', file: '29-admin-sessions.png', as: 'admin', url: '/admin/sessions.php' },
  { n: '30', file: '30-admin-parametres.png', as: 'admin', url: '/admin/settings.php' },
  { n: '31', file: '31-admin-email-mfa.png', as: 'admin', url: '/admin/email.php', blur: ['input[type=password]', '[name=pass]'] },
  { n: '32', file: '32-oauth-consentement.png', as: 'user', url: AUTHORIZE },
  { n: '33', file: '33-oauth-acces-refuse.png', as: 'norole', url: AUTHORIZE },
];

function otp(email) {
  const code = `chdir(${JSON.stringify(ROOT)}); require 'includes/functions.php';`
    + `$u = iam_find_user(${JSON.stringify(email)}); echo iam_generate_otp((int) $u['id'], 'email');`;
  return execFileSync('php', ['-r', code], { encoding: 'utf8' }).trim();
}

async function login(b, email, { stopAtMfa = false } = {}) {
  await b.goto(`${BASE}/login.php`);
  await b.evalAndWait(fill({ '#identifier': email, '#password': PASSWORD }) + 'document.querySelector("form").submit()');
  if ((await b.url()).includes('/mfa.php') && !stopAtMfa) {
    await b.evalAndWait(fill({ '[name=code]': otp(email) }) + 'document.querySelector("[name=code]").form.submit()');
  }
}

async function blurAll(b, selectors = []) {
  if (!selectors.length) return;
  await b.eval(`document.querySelectorAll(${JSON.stringify(selectors.join(','))}).forEach(e=>{e.style.filter='blur(5px)'})`);
}

const wanted = process.argv.slice(2);
const steps = STEPS.filter((s) => !wanted.length || wanted.includes(s.n));
mkdirSync(OUT, { recursive: true });

// Un navigateur (donc une session) par compte
const groups = new Map();
for (const s of steps) {
  const key = `${s.as ?? `anon-${s.n}`}@${s.w ?? 1440}`;
  if (!groups.has(key)) groups.set(key, []);
  groups.get(key).push(s);
}

for (const [group, list] of groups) {
  const [key, w] = group.split('@');
  const b = await Browser.launch({ width: Number(w), height: Math.round(Number(w) * 0.625) });
  try {
    if (key === 'user-before-mfa') await login(b, ACCOUNTS.user, { stopAtMfa: true });
    else if (ACCOUNTS[key]) await login(b, ACCOUNTS[key]);
    for (const s of list) {
      if (s.url) await b.goto(s.url.startsWith('http') ? s.url : BASE + s.url);
      if (s.run) await s.run(b);
      await blurAll(b, s.blur);
      await sleep(250);
      await b.screenshot(join(OUT, s.file));
      console.log(`  [OK] ${s.file}  (${await b.url()})`);
    }
  } catch (e) {
    console.log(`  [ÉCHEC] ${key} : ${e.message}`);
  } finally {
    await b.close();
  }
}
