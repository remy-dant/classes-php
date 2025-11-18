<?php
session_start();

// Page de test pour l'exercice — Inscription / Connexion
// Configuration : modifiez `config.php` ou les variables ci-dessous
$configFile = __DIR__ . '/config.php';
if (file_exists($configFile)) require $configFile;
// fallback si config non présente
$db_host = $db_host ?? '127.0.0.1';
$db_name = $db_name ?? 'your_db';
$db_user = $db_user ?? 'db_user';
$db_pass = $db_pass ?? 'db_pass';

require_once __DIR__ . '/user.php';
require_once __DIR__ . '/user-pdo.php';

$errors = [];
$success = null;

// POST handlers: registration (default) and login (when form=login)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['form']) && $_POST['form'] === 'login') {
        // Login via PDO
        $login_ident = trim($_POST['login_ident'] ?? '');
        $login_pass = $_POST['login_pass'] ?? '';
        if ($login_ident === '' || $login_pass === '') {
            $errors[] = 'Identifiant et mot de passe requis.';
        } else {
            try {
                $dsn = "mysql:host={$db_host};dbname={$db_name};charset=utf8mb4";
                $pdo = new PDO($dsn, $db_user, $db_pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
                $stmt = $pdo->prepare('SELECT id, login, password, email, firstname, lastname FROM utilisateurs WHERE login = :login LIMIT 1');
                $stmt->execute([':login' => $login_ident]);
                $userRow = $stmt->fetch(PDO::FETCH_ASSOC);
                if (!$userRow || !password_verify($login_pass, $userRow['password'])) {
                    $errors[] = 'Identifiant ou mot de passe invalide.';
                } else {
                    $_SESSION['user'] = [
                        'id' => (int)$userRow['id'],
                        'login' => $userRow['login'],
                        'email' => $userRow['email'],
                        'firstname' => $userRow['firstname'],
                        'lastname' => $userRow['lastname'],
                    ];
                    header('Location: profile.php');
                    exit;
                }
            } catch (PDOException $e) {
                $errors[] = 'Erreur de connexion PDO : ' . $e->getMessage();
            }
        }
    } else {
        // Registration
        $connType = isset($_POST['conn_type']) && $_POST['conn_type'] === 'mysqli' ? 'mysqli' : 'pdo';
        $login = trim($_POST['login'] ?? '');
        $password = $_POST['password'] ?? '';
        $email = trim($_POST['email'] ?? '');
        $firstname = trim($_POST['firstname'] ?? '');
        $lastname = trim($_POST['lastname'] ?? '');

        if ($login === '' || $password === '' || $email === '' || $firstname === '' || $lastname === '') {
            $errors[] = 'Tous les champs sont requis.';
        } else {
            if ($connType === 'mysqli') {
                // MySQLi registration
                try {
                    $mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
                    if ($mysqli->connect_errno) {
                        throw new Exception('Erreur MySQLi: ' . $mysqli->connect_error);
                    }
                    $user = new User($mysqli);
                    $res = $user->register($login, $password, $email, $firstname, $lastname);
                    if ($res === false) {
                        $errors[] = 'Inscription échouée avec MySQLi.';
                    } else {
                        $_SESSION['user'] = [
                            'id' => (int)($res['id'] ?? 0),
                            'login' => $res['login'] ?? $login,
                            'email' => $res['email'] ?? $email,
                            'firstname' => $res['firstname'] ?? $firstname,
                            'lastname' => $res['lastname'] ?? $lastname,
                        ];
                        header('Location: profile.php');
                        exit;
                    }
                } catch (Exception $e) {
                    $errors[] = $e->getMessage();
                }
            } else {
                // PDO registration
                try {
                    $dsn = "mysql:host={$db_host};dbname={$db_name};charset=utf8mb4";
                    $pdo = new PDO($dsn, $db_user, $db_pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
                    $user = new Userpdo($pdo);
                    $res = $user->register($login, $password, $email, $firstname, $lastname);
                    if ($res === false) {
                        $errors[] = 'Inscription échouée avec PDO.';
                    } else {
                        $_SESSION['user'] = [
                            'id' => (int)($res['id'] ?? 0),
                            'login' => $res['login'] ?? $login,
                            'email' => $res['email'] ?? $email,
                            'firstname' => $res['firstname'] ?? $firstname,
                            'lastname' => $res['lastname'] ?? $lastname,
                        ];
                        header('Location: profile.php');
                        exit;
                    }
                } catch (PDOException $e) {
                    $errors[] = 'Erreur PDO: ' . $e->getMessage();
                }
            }
        }
    }
}

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <title>Inscription — Test classes-php</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="top-left">
        <label for="conn_type_select">Type :</label>
        <select id="conn_type_select">
            <option value="pdo" <?= (isset($connType) && $connType === 'pdo') ? 'selected' : '' ?>>PDO</option>
            <option value="mysqli" <?= (isset($connType) && $connType === 'mysqli') ? 'selected' : '' ?>>MySQLi</option>
        </select>
    </div>

    <div class="modal">
    <div class="panel-signup">
    <h1>Inscription</h1>

    <?php if (!empty($errors)): ?>
        <div class="msg err">
            <strong>Erreurs :</strong>
            <ul>
                <?php foreach ($errors as $e): ?>
                    <li><?= h($e) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <?php if ($success): ?>
        <div class="msg ok"><?= h($success) ?></div>
    <?php endif; ?>

    <form method="post" novalidate>
        <input type="hidden" name="conn_type" id="conn_type_hidden" value="<?= isset($connType) ? h($connType) : 'pdo' ?>">

        <div class="row">
            <div style="flex:1">
                <label for="firstname">Prénom :</label>
                <input id="firstname" name="firstname" value="<?= h($_POST['firstname'] ?? '') ?>" required>
            </div>
            <div style="flex:1">
                <label for="lastname">Nom :</label>
                <input id="lastname" name="lastname" value="<?= h($_POST['lastname'] ?? '') ?>" required>
            </div>
        </div>

        <label for="login">Identifiant :</label>
        <input id="login" name="login" value="<?= h($_POST['login'] ?? '') ?>" required>

        <label for="password">Mot de passe :</label>
        <div class="input-with-icon">
            <button type="button" class="eye-toggle" aria-pressed="false" aria-label="Afficher ou masquer le mot de passe">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M12 5C7 5 2.73 8.11 1 12C2.73 15.89 7 19 12 19C17 19 21.27 15.89 23 12C21.27 8.11 17 5 12 5Z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </button>
            <input id="password" name="password" type="password" required>
        </div>

        <label for="email">Email :</label>
        <input id="email" name="email" type="email" value="<?= h($_POST['email'] ?? '') ?>" required>

        <button type="submit" class="btn-primary">Inscription</button>
    </form>

        <div class="alt-action">
            <button id="openLoginBtn" class="alt-action-btn" type="button">Vous avez déjà un compte ? Connectez-vous</button>
        </div>
    </div><!-- .panel-signup -->

    <div class="panel-login hidden">
        <h2>Se connecter</h2>
        <form id="loginFormInline" method="post" action="#">
            <input type="hidden" name="form" value="login">
            <label for="login_ident">Identifiant</label>
            <input id="login_ident" name="login_ident" type="text" autocomplete="username">

            <label for="login_pass">Mot de passe</label>
            <div class="input-with-icon">
                <button type="button" class="eye-toggle" aria-pressed="false" aria-label="Afficher ou masquer le mot de passe">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M12 5C7 5 2.73 8.11 1 12C2.73 15.89 7 19 12 19C17 19 21.27 15.89 23 12C21.27 8.11 17 5 12 5Z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>
                <input id="login_pass" name="login_pass" type="password" autocomplete="current-password">
            </div>

            <button id="doLoginInline" class="btn-primary" disabled type="submit">Se connecter</button>
        </form>

        <div class="alt-action" style="margin-top:10px;">
            <button id="toSignupBtn" class="alt-action-btn" type="button">Pas de compte ? Inscrivez-vous</button>
        </div>
    </div><!-- .panel-login -->

    </div><!-- .modal -->

    <script>
        // synchronise la sélection en haut à gauche avec le champ caché du formulaire
        (function(){
            var select = document.getElementById('conn_type_select');
            var hidden = document.getElementById('conn_type_hidden');
            if (!select || !hidden) return;
            // initial sync
            hidden.value = select.value;
            select.addEventListener('change', function(){ hidden.value = select.value; });
        })();
    </script>

</body>
</html>

<script>
// Switch panels inside the modal: show login panel in place of signup
document.addEventListener('DOMContentLoaded', function(){
    var openLoginBtn = document.getElementById('openLoginBtn');
    var panelSignup = document.querySelector('.panel-signup');
    var panelLogin = document.querySelector('.panel-login');
    var loginCloseTop = document.getElementById('loginCloseTop');
    var toSignupBtn = document.getElementById('toSignupBtn');

    function showLoginInline(){
        if (panelSignup) panelSignup.classList.add('hidden');
        if (panelLogin) panelLogin.classList.remove('hidden');
        var ident = document.getElementById('login_ident');
        if (ident) ident.focus();
    }
    function showSignupInline(){
        if (panelLogin) panelLogin.classList.add('hidden');
        if (panelSignup) panelSignup.classList.remove('hidden');
    }

    if (openLoginBtn) openLoginBtn.addEventListener('click', function(e){ e.preventDefault(); showLoginInline(); });
    if (loginCloseTop) loginCloseTop.addEventListener('click', function(e){ e.preventDefault(); showSignupInline(); });
    if (toSignupBtn) toSignupBtn.addEventListener('click', function(e){ e.preventDefault(); showSignupInline(); window.scrollTo(0,0); });

    // enable login button when both fields non-empty (inline)
    var doLoginInline = document.getElementById('doLoginInline');
    var identInline = document.getElementById('login_ident');
    var passInline = document.getElementById('login_pass');
    function checkLoginEnableInline(){
        if (!doLoginInline) return;
        doLoginInline.disabled = !(identInline && passInline && identInline.value.trim() && passInline.value.trim());
    }
    if (identInline) identInline.addEventListener('input', checkLoginEnableInline);
    if (passInline) passInline.addEventListener('input', checkLoginEnableInline);

    // eye toggle for password fields (registration + inline login)
    var eyeBtns = document.querySelectorAll('.eye-toggle');
    eyeBtns.forEach(function(btn){
        btn.addEventListener('click', function(){
            var input = btn.nextElementSibling;
            if (!input) return;
            if (input.type === 'password') {
                input.type = 'text';
                btn.setAttribute('aria-pressed','true');
            } else {
                input.type = 'password';
                btn.setAttribute('aria-pressed','false');
            }
        });
    });
});
</script>
