<?php
// IAM-Local — Configuration de l'e-mail d'envoi MFA
require_once __DIR__ . '/_guard.php';
require_once __DIR__ . '/../includes/mailer.php';

$db = db();
$msg = '';
$err = '';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$cfg       = iam_smtp_config();
$smtpReady = iam_smtp_configured();
$mailMode  = iam_mail_mode_label();

// Traitement POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $err = 'Session expirée.';
    } elseif ($action === 'test') {
        [$ok, $smtpErr, $testTo] = iam_test_smtp();
        $msg = $ok ? 'Test envoyé à ' . htmlspecialchars($testTo) . ' — vérifiez votre boîte de réception.' : '';
        $err = $ok ? '' : 'Échec de l\'envoi : <a href="#depannage">' . htmlspecialchars($smtpErr) . '</a>';
    } else {
        // Save SMTP
        iam_save_smtp_config([
            'host'      => trim($_POST['host'] ?? ''),
            'port'      => trim($_POST['port'] ?? ''),
            'user'      => trim($_POST['user'] ?? ''),
            'pass'      => $_POST['pass'] ?? '',
            'from'      => trim($_POST['from'] ?? ''),
            'from_name' => trim($_POST['from_name'] ?? ''),
        ]);
        iam_audit('smtp_updated', 'Configuration SMTP modifiée', $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
        $msg = 'Paramètres SMTP enregistrés. Envoyez maintenant l\'e-mail de test ci-dessous.';
        $cfg = iam_smtp_config();
        $smtpReady = iam_smtp_configured();
        $mailMode  = iam_mail_mode_label();
    }
}

$pageTitle = 'E-mail &amp; MFA';
$active = 'email';
include __DIR__ . '/_header.php';

// État du guide en 3 étapes
$step1 = $smtpReady ? 'done' : 'active';
$step2 = $smtpReady ? 'done' : '';
$step3 = $smtpReady ? 'active' : '';
?>
<?php if ($msg): ?><div class="alert alert-success"><?php echo $msg; ?></div><?php endif; ?>
<?php if ($err): ?><div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <?php echo $err; ?></div><?php endif; ?>

<?php if ($smtpReady): ?>
<div class="alert alert-success">
    <strong><i class="fas fa-circle-check"></i> Envoi MFA configuré.</strong>
    Serveur <span class="mono"><?php echo htmlspecialchars($cfg['host']); ?></span> (port <?php echo (int) $cfg['port']; ?>), expéditeur <span class="mono"><?php echo htmlspecialchars($cfg['user']); ?></span>.<br>
    L'e-mail de test de l'étape 3 confirme que le cycle complet fonctionne.
</div>
<?php else: ?>
<div class="alert alert-warning">
    <strong><i class="fas fa-triangle-exclamation"></i> Envoi MFA non configuré.</strong> Les codes OTP sont affichés à l'écran en mode démonstration.<br>
    Suivez les 3 étapes ci-dessous (la clé générée par Google est un « mot de passe d'application »).
</div>
<?php endif; ?>

<div class="steps">
    <div class="step <?php echo $step1; ?>">
        <span class="step-num"><?php echo $smtpReady ? '<i class="fas fa-check"></i>' : '1'; ?></span>
        <span class="step-label">Créer la clé Google</span>
    </div>
    <div class="step <?php echo $step2; ?>">
        <span class="step-num"><?php echo $smtpReady ? '<i class="fas fa-check"></i>' : '2'; ?></span>
        <span class="step-label">Renseigner le serveur SMTP</span>
    </div>
    <div class="step <?php echo $step3; ?>">
        <span class="step-num">3</span>
        <span class="step-label">Recevoir l'e-mail de test</span>
    </div>
</div>

<!-- 1. CRÉER LA CLÉ GOOGLE -->
<div class="card" style="margin-top:15px;">
    <div class="card-body">
        <div class="card-title"><i class="fab fa-google"></i> Créer la clé sur votre compte Google</div>
        <p class="text-muted" style="font-size:13px;">
            Cette clé remplace votre mot de passe pour l'envoi d'e-mails. Aucune application à créer.
        </p>
        <ol style="padding-left:20px; font-size:14px; margin-top:8px;">
            <li><strong>Activer la validation en 2 étapes</strong> (obligatoire, ne marche qu'une fois) :
                aller sur <strong>https://myaccount.google.com/security</strong> → section « Comment vous connecter à Google »
                → <strong>Validation en 2 étapes</strong> → <strong>Commencer</strong> → suivez l'assistant (numéro de téléphone + code par SMS).
                Si elle est déjà <strong>activée</strong>, passez à l'étape suivante.</li>
            <li>Ouvrir <strong>https://myaccount.google.com/apppasswords</strong>.</li>
            <li>Dans la boîte <strong>« Nom de l'application »</strong> : taper <span class="mono">IAM ACSI</span> → cliquer <strong>Créer</strong>.</li>
            <li>Google affiche une clé de <strong>16 lettres</strong> (format <span class="mono">abcd efgh ijkl mnop</span>) → <strong>copier la clé</strong>.</li>
            <li>La coller dans le champ <strong>« Mot de passe »</strong> de l'étape 2 ci-dessous (les espaces sont facultatifs).</li>
        </ol>
    </div>
</div>

<!-- 2. RENSEIGNER LE SMTP -->
<div class="card" style="margin-top:15px;">
    <div class="card-body">
        <div class="card-title"><i class="fas fa-server"></i> Renseigner les réglages d'envoi</div>
        <p class="form-hint" style="font-size:13px;">
            Pour Gmail : serveur <span class="mono">smtp.gmail.com</span>, port <span class="mono">465</span>,
            utilisateur = votre adresse Gmail complète, mot de passe = la <strong>clé de 16 lettres</strong> de l'étape 1.
            (Outlook : <span class="mono">smtp.office365.com</span> port 587 avec votre mot de passe habituel ou une clé applicative.)
        </p>
        <form method="POST">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="form-row">
                <div class="form-group">
                    <label>Serveur SMTP (hôte)</label>
                    <input type="text" name="host" class="form-control" value="<?php echo htmlspecialchars($cfg['host']); ?>" placeholder="smtp.gmail.com">
                </div>
                <div class="form-group">
                    <label>Port</label>
                    <input type="number" name="port" class="form-control" value="<?php echo (int) $cfg['port']; ?>" min="1" max="65535" placeholder="465">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Utilisateur (adresse Gmail)</label>
                    <input type="text" name="user" class="form-control" value="<?php echo htmlspecialchars($cfg['user']); ?>" placeholder="monmail@gmail.com" autocomplete="off">
                </div>
                <div class="form-group">
                    <label>Mot de passe (la clé de 16 lettres)</label>
                    <input type="password" name="pass" class="form-control" value="" placeholder="<?php echo $smtpReady ? '•••••••• (vide = conserver)' : 'abcd efgh ijkl mnop'; ?>" autocomplete="new-password">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Expédition (From)</label>
                    <input type="email" name="from" class="form-control" value="<?php echo htmlspecialchars($cfg['from']); ?>" placeholder="vide = utiliser l'utilisateur">
                </div>
                <div class="form-group">
                    <label>Nom affiché</label>
                    <input type="text" name="from_name" class="form-control" value="<?php echo htmlspecialchars($cfg['from_name']); ?>" placeholder="IAM ACSI">
                </div>
            </div>
            <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Enregistrer</button>
        </form>
    </div>
</div>

<!-- 3. TESTER -->
<div class="cards-grid" style="margin-top:15px;">
    <div class="card">
        <div class="card-body">
            <div class="card-title"><i class="fas fa-shield-halved"></i> Vérification MFA</div>
            <table class="table" style="font-size:14px;">
                <tr>
                    <th>Mode d'envoi actif</th>
                    <td>
                        <?php if ($smtpReady): ?>
                            <span class="badge badge-success"><?php echo htmlspecialchars($mailMode); ?></span>
                        <?php else: ?>
                            <span class="badge badge-warning"><?php echo htmlspecialchars($mailMode); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <th>MFA obligatoire</th>
                    <td><?php echo MFA_FORCE_ALL ? '<span class="badge badge-success">Activé (sauf admin)</span>' : '<span class="badge badge-secondary">Par utilisateur</span>'; ?></td>
                </tr>
                <tr><th>Durée de validité OTP</th><td><?php echo (int) OTP_LIFETIME; ?> secondes</td></tr>
                <tr><th>Essais maximum</th><td><?php echo (int) OTP_MAX_TRIES; ?></td></tr>
            </table>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            <div class="card-title"><i class="fas fa-envelope"></i> Envoyer un e-mail de test</div>
            <p class="text-muted" style="font-size:13px;">Vérifie que le serveur d'envoi fonctionne réellement.</p>
            <form method="POST">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="test">
                <div class="form-group">
                    <label>Adresse de destination</label>
                    <input type="email" name="test_to" class="form-control" value="<?php echo htmlspecialchars($iamAdmin['email'] ?? ''); ?>" placeholder="admin@exemple.ci">
                </div>
                <button type="submit" class="btn btn-primary"><i class="fas fa-paper-plane"></i> Envoyer l'e-mail de test</button>
            </form>
            <p class="form-hint" style="margin-top:8px; font-size:12px;">
                Vérifiez ensuite le cycle complet : déconnexion → connexion d'un utilisateur non-admin → code reçu par e-mail sur la page MFA.
            </p>
        </div>
    </div>
</div>

<!-- DÉPANNAGE -->
<div class="card" style="margin-top:15px;" id="depannage">
    <div class="card-body">
        <div class="card-title"><i class="fas fa-wrench"></i> Dépannage</div>
        <table class="table" style="font-size:13px;">
            <tr><th style="width:40%;">535 5.7.8 Username and Password not accepted</th><td>Le mot de passe Gmail normal est refusé : il faut la <strong>clé de 16 lettres</strong> créée sur <span class="mono">myaccount.google.com/apppasswords</span> (validation en 2 étapes activée au préalable).</td></tr>
            <tr><th>« Échec de l'envoi » au test</th><td>Vérifiez l'hôte/le port (<span class="mono">smtp.gmail.com</span> / <span class="mono">465</span>), que l'utilisateur est bien l'adresse Gmail complète, et que la clé n'a pas d'espace parasite.</td></tr>
            <tr><th>Pas de « Mots de passe d'application » sur la page Google</th><td>Activez d'abord la validation en 2 étapes sur <span class="mono">myaccount.google.com/security</span>, sinon l'option n'apparaît pas.</td></tr>
        </table>
    </div>
</div>

<p class="form-hint" style="margin-top:12px; font-size:12px;">
    <i class="fas fa-circle-question"></i> La vérification MFA envoie le code à l'adresse e-mail de chaque utilisateur (Admin → Utilisateurs). Pensez à renseigner l'e-mail des utilisateurs dans leur fiche.
</p>
<?php include __DIR__ . '/_footer.php'; ?>