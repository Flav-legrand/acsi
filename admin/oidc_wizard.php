<?php
require_once __DIR__ . '/_guard.php';
require_once __DIR__ . '/../includes/platforms/IamServiceProvider.php';

if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$registry = IamLocal\Platforms\IamServiceProvider::platforms();
$pageTitle = 'Nouvelle application OAuth / OIDC';
$active = 'oauth';
include __DIR__ . '/_header.php';
?>
<div class="oidc-wizard-page">
    <div class="d-flex justify-between align-center mb-3">
        <div><a href="<?php echo IAM_BASE_URL; ?>/admin/oidc_apps.php">← Applications OAuth / OIDC</a><h2>Nouvelle application</h2></div>
    </div>
    <ol class="wizard-progress" aria-label="Étapes de configuration">
        <li aria-current="step">Plateforme &amp; application</li><li>OAuth / OIDC</li><li>Rôles &amp; validation</li>
    </ol>
    <form method="POST" action="<?php echo IAM_BASE_URL; ?>/admin/oidc_apps.php" id="oidcWizardForm">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <input type="hidden" name="action" value="create_client">
        <input type="hidden" name="platform" id="wizardPlatform" value="laravel">

        <section class="wizard-step" data-step="0">
            <h3>Choisir la plateforme</h3>
            <div class="platform-grid" role="radiogroup" aria-label="Plateforme">
                <?php foreach ($registry->all() as $key => $adapter): ?>
                    <button type="button" class="platform-option <?php echo $key === 'laravel' ? 'selected' : ''; ?>" role="radio" aria-checked="<?php echo $key === 'laravel' ? 'true' : 'false'; ?>"
                        data-platform="<?php echo htmlspecialchars($key); ?>"
                        data-client-type="<?php echo htmlspecialchars($adapter->getDefaultClientType()); ?>"
                        data-redirects="<?php echo htmlspecialchars(json_encode($adapter->getDefaultRedirectUris()), ENT_QUOTES); ?>"
                        data-logout="<?php echo htmlspecialchars(json_encode($adapter->getDefaultPostLogoutUris()), ENT_QUOTES); ?>"
                        data-scopes="<?php echo htmlspecialchars(json_encode($adapter->getDefaultScopes()), ENT_QUOTES); ?>"
                        data-grants="<?php echo htmlspecialchars(json_encode($adapter->getDefaultGrantTypes()), ENT_QUOTES); ?>">
                        <span class="platform-mark"><i class="fas fa-code"></i></span>
                        <strong><?php echo htmlspecialchars($adapter->getLabel()); ?></strong>
                        <small><?php echo htmlspecialchars($adapter->getDescription()); ?></small>
                    </button>
                <?php endforeach; ?>
            </div>
            <h3>Informations générales</h3>
            <div class="wizard-fields">
                <div class="form-group"><label for="wizardName">Nom de l’application *</label><input id="wizardName" class="form-control" name="name" maxlength="120" required placeholder="Gestion des Salaires"></div>
                <div class="form-group"><label for="wizardSlug">Slug</label><input id="wizardSlug" class="form-control" name="slug" maxlength="80" pattern="[a-z0-9]+(-[a-z0-9]+)*" placeholder="gestion-des-salaires"><small>Identifiant lisible; rendu unique à l’enregistrement.</small></div>
                <div class="form-group"><label for="wizardDescription">Description</label><textarea id="wizardDescription" class="form-control" name="description" rows="2"></textarea></div>
                <div class="form-group"><label for="wizardVersion">Version de la plateforme</label><input id="wizardVersion" class="form-control" name="platform_version" placeholder="11.x"></div>
                <div class="form-group"><label for="wizardBaseUrl">URL de base *</label><input id="wizardBaseUrl" class="form-control" type="url" name="base_url" required placeholder="https://application.example.com"></div>
                <fieldset class="form-group"><legend>Type de client OAuth</legend>
                    <label class="choice-row"><input type="radio" name="client_type" value="confidential" checked><span><strong>Confidentiel</strong><small>Secret hashé, conservé uniquement sur le serveur.</small></span></label>
                    <label class="choice-row"><input type="radio" name="client_type" value="public"><span><strong>Public</strong><small>Aucun secret. PKCE S256 obligatoire.</small></span></label>
                    <p id="clientTypeHint" class="adapter-hint">Laravel propose un client confidentiel; ce choix reste modifiable.</p>
                </fieldset>
                <label class="choice-row"><input type="checkbox" name="is_active" checked><span><strong>Activer à la création</strong></span></label>
            </div>
            <div class="wizard-actions"><a class="btn btn-outline" href="<?php echo IAM_BASE_URL; ?>/admin/oidc_apps.php">Annuler</a><button type="button" class="btn btn-primary" data-next>Continuer</button></div>
        </section>

        <section class="wizard-step" data-step="1" hidden>
            <h3>Configuration OAuth / OIDC</h3>
            <div class="form-group"><label>Redirect URIs</label><div id="wizardRedirectRows"></div><button type="button" class="btn btn-outline btn-sm" data-add-uri="wizardRedirectRows">+ Ajouter une URI</button></div>
            <div class="form-group"><label>Post-logout redirect URIs</label><div id="wizardLogoutRows"></div><button type="button" class="btn btn-outline btn-sm" data-add-uri="wizardLogoutRows">+ Ajouter une URI</button></div>
            <div class="wizard-fields">
                <fieldset class="form-group"><legend>Scopes autorisés</legend><?php foreach (['openid', 'profile', 'email', 'roles', 'offline_access'] as $scope): ?><label class="choice-row"><input type="checkbox" name="scopes[]" value="<?php echo $scope; ?>"><span><?php echo $scope; ?></span></label><?php endforeach; ?></fieldset>
                <fieldset class="form-group"><legend>Grant types</legend><?php foreach (['authorization_code', 'refresh_token', 'client_credentials'] as $grant): ?><label class="choice-row"><input type="checkbox" name="grant_types[]" value="<?php echo $grant; ?>"><span><?php echo $grant; ?></span></label><?php endforeach; ?></fieldset>
                <div class="form-group"><label for="wizardTokenLifetime">Durée access token (secondes)</label><input id="wizardTokenLifetime" class="form-control" type="number" min="60" max="86400" name="access_token_minutes" value="60" required><small>Valeur exprimée en minutes.</small></div>
                <div class="form-group"><label for="wizardRefreshLifetime">Durée refresh token (jours)</label><input id="wizardRefreshLifetime" class="form-control" type="number" min="1" max="365" name="refresh_token_days" value="30" required></div>
                <label class="choice-row"><input type="checkbox" name="refresh_enabled" checked><span><strong>Autoriser le refresh token</strong><small>Le scope offline_access doit aussi être demandé.</small></span></label>
                <label class="choice-row"><input id="wizardPkce" type="checkbox" name="pkce_required"><span><strong>Exiger PKCE S256</strong><small>Toujours forcé pour un client public.</small></span></label>
            </div>
            <div class="wizard-actions"><button type="button" class="btn btn-outline" data-back>Retour</button><button type="button" class="btn btn-primary" data-next>Continuer</button></div>
        </section>

        <section class="wizard-step" data-step="2" hidden>
            <h3>Rôles IAM vers application</h3>
            <p class="text-muted">Le mapping est renvoyé uniquement avec le scope <code>roles</code>. La création locale JIT reste à exécuter côté application.</p>
            <div id="wizardRoleRows"></div><button type="button" class="btn btn-outline btn-sm" data-add-role>+ Ajouter un mapping</button>
            <label class="choice-row"><input type="checkbox" name="jit_provisioning"><span><strong>Activer le JIT côté client</strong><small>Le snippet signale cette option; l’application cliente doit créer le compte local.</small></span></label>
            <div class="wizard-actions"><button type="button" class="btn btn-outline" data-back>Retour</button><button type="submit" class="btn btn-success"><i class="fas fa-plus"></i> Créer l’application</button></div>
        </section>
    </form>
</div>
<style>
.wizard-progress{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;padding:0;margin:16px 0 24px;list-style:none}.wizard-progress li{padding:10px;border-bottom:2px solid var(--border);color:var(--muted);font-size:13px}.wizard-progress li[aria-current=step]{border-color:#087e8b;color:#153942;font-weight:700}.wizard-step[hidden]{display:none}.wizard-step h3{margin:22px 0 12px;font-size:17px}.platform-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:9px}.platform-option{display:grid;grid-template-columns:38px 1fr;gap:4px 10px;text-align:left;padding:12px;border:1px solid var(--border);border-radius:6px;background:#fff;color:inherit;cursor:pointer}.platform-option.selected{border:2px solid #087e8b;background:#eff9f8}.platform-option small{grid-column:2;color:var(--muted);line-height:1.4}.platform-mark{grid-row:span 2;display:grid;place-items:center;width:36px;aspect-ratio:1;border-radius:5px;background:#e8f1f2;color:#087e8b}.wizard-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.choice-row{display:flex;align-items:flex-start;gap:9px;margin:8px 0}.choice-row span{display:grid;gap:3px}.choice-row small,.form-group small{color:var(--muted)}.adapter-hint{color:var(--muted);font-size:12px}.wizard-actions{display:flex;justify-content:space-between;gap:10px;margin-top:22px}.wizard-uri-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;margin:7px 0}.wizard-uri-row input{min-width:0}@media(max-width:700px){.wizard-fields{grid-template-columns:1fr}.wizard-progress{gap:4px}.wizard-progress li{font-size:11px;text-align:center;padding:8px 4px}}
</style>
<script>
(() => {
    const form = document.getElementById('oidcWizardForm');
    const steps = [...form.querySelectorAll('.wizard-step')];
    const progress = [...document.querySelectorAll('.wizard-progress li')];
    const platformField = document.getElementById('wizardPlatform');
    const baseField = document.getElementById('wizardBaseUrl');
    const radioType = [...form.querySelectorAll('[name="client_type"]')];
    let stepIndex = 0;
    let defaults = { redirects: [], logout: [], scopes: [], grants: [] };
    const replaceBase = value => String(value).replaceAll('{base_url}', baseField.value.replace(/\/$/, ''));
    const showStep = index => {
        stepIndex = index;
        steps.forEach((section, i) => section.hidden = i !== index);
        progress.forEach((item, i) => i === index ? item.setAttribute('aria-current', 'step') : item.removeAttribute('aria-current'));
    };
    const setRows = (id, name, values) => {
        const container = document.getElementById(id); container.replaceChildren();
        values.forEach(value => addUriRow(container, name, replaceBase(value)));
    };
    const addUriRow = (container, name, value = '') => {
        const row = document.createElement('div'); row.className = 'wizard-uri-row';
        const input = document.createElement('input'); input.className = 'form-control'; input.name = name; input.type = 'url'; input.value = value; input.placeholder = 'https://application.example.com/callback';
        const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'btn btn-outline btn-sm'; remove.textContent = '×'; remove.title = 'Supprimer'; remove.addEventListener('click', () => row.remove());
        row.append(input, remove); container.append(row);
    };
    const selectPlatform = button => {
        document.querySelectorAll('.platform-option').forEach(option => { const selected = option === button; option.classList.toggle('selected', selected); option.setAttribute('aria-checked', selected ? 'true' : 'false'); });
        platformField.value = button.dataset.platform;
        defaults = { redirects: JSON.parse(button.dataset.redirects), logout: JSON.parse(button.dataset.logout), scopes: JSON.parse(button.dataset.scopes), grants: JSON.parse(button.dataset.grants) };
        const suggestedType = button.dataset.clientType;
        radioType.forEach(radio => radio.checked = radio.value === suggestedType);
        document.querySelectorAll('[name="scopes[]"]').forEach(input => input.checked = defaults.scopes.includes(input.value));
        document.querySelectorAll('[name="grant_types[]"]').forEach(input => input.checked = defaults.grants.includes(input.value));
        setRows('wizardRedirectRows', 'redirect_uris[]', defaults.redirects);
        setRows('wizardLogoutRows', 'post_logout_redirect_uris[]', defaults.logout);
        syncClientType();
    };
    const syncClientType = () => {
        const isPublic = form.querySelector('[name="client_type"]:checked').value === 'public';
        const pkce = document.getElementById('wizardPkce'); pkce.checked = isPublic || pkce.checked; pkce.disabled = isPublic;
        if (isPublic) pkce.checked = true;
        document.getElementById('clientTypeHint').textContent = `${document.querySelector('.platform-option.selected strong').textContent} : type suggéré ${isPublic ? 'public + PKCE' : 'confidentiel'}. Le type est modifiable.`;
    };
    document.querySelectorAll('.platform-option').forEach(button => button.addEventListener('click', () => selectPlatform(button)));
    radioType.forEach(radio => radio.addEventListener('change', syncClientType));
    form.querySelectorAll('[data-next]').forEach(button => button.addEventListener('click', () => {
        const invalid = [...steps[stepIndex].querySelectorAll('input[required]')].find(input => !input.checkValidity());
        if (invalid) { invalid.reportValidity(); return; }
        showStep(Math.min(stepIndex + 1, steps.length - 1));
    }));
    form.querySelectorAll('[data-back]').forEach(button => button.addEventListener('click', () => showStep(Math.max(0, stepIndex - 1))));
    document.querySelectorAll('[data-add-uri]').forEach(button => button.addEventListener('click', () => addUriRow(document.getElementById(button.dataset.addUri), button.dataset.addUri === 'wizardRedirectRows' ? 'redirect_uris[]' : 'post_logout_redirect_uris[]')));
    document.querySelector('[data-add-role]').addEventListener('click', () => {
        const row = document.createElement('div'); row.className = 'oidc-map-row';
        const iam = document.createElement('input'); iam.className = 'form-control'; iam.name = 'iam_role[]'; iam.placeholder = 'Rôle IAM';
        const arrow = document.createElement('span'); arrow.textContent = '→';
        const app = document.createElement('input'); app.className = 'form-control'; app.name = 'app_role[]'; app.placeholder = 'Rôle de l’application';
        const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'btn btn-outline btn-sm'; remove.textContent = '×'; remove.addEventListener('click', () => row.remove());
        row.append(iam, arrow, app, remove); document.getElementById('wizardRoleRows').append(row);
    });
    document.getElementById('wizardBaseUrl').addEventListener('change', () => selectPlatform(document.querySelector('.platform-option.selected')));
    document.getElementById('wizardName').addEventListener('input', event => {
        const slug = document.getElementById('wizardSlug');
        if (!slug.dataset.edited) slug.value = event.target.value.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    });
    document.getElementById('wizardSlug').addEventListener('input', event => event.target.dataset.edited = '1');
    document.getElementById('wizardRefreshLifetime').name = 'refresh_token_days';
    selectPlatform(document.querySelector('.platform-option.selected'));
})();
</script>
<?php include __DIR__ . '/_footer.php'; ?>