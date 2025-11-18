<?php
session_start();
// profile.php - affiche et permet de modifier les infos de l'utilisateur connecté
require_once __DIR__ . '/user-pdo.php';

$configFile = __DIR__ . '/config.php';
if (file_exists($configFile)) require $configFile;
// valeurs par défaut si config.php absent
$db_host = $db_host ?? '127.0.0.1';
$db_name = $db_name ?? 'your_db';
$db_user = $db_user ?? 'db_user';
$db_pass = $db_pass ?? 'db_pass';

if (!isset($_SESSION['user']) || empty($_SESSION['user']['id'])) {
    header('Location: index.php');
    exit;
}

$user = $_SESSION['user'];
$errors = [];
$success = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action']) && $_POST['action'] === 'logout') {
        // logout
        session_unset();
        session_destroy();
        header('Location: index.php');
        exit;
    }

    if (isset($_POST['action']) && $_POST['action'] === 'modify') {
        $firstname = trim($_POST['firstname'] ?? '');
        $lastname = trim($_POST['lastname'] ?? '');
        $login = trim($_POST['login'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($firstname === '' || $lastname === '' || $login === '' || $email === '') {
            $errors[] = 'Tous les champs sauf le mot de passe sont requis.';
        } else {
            try {
                $dsn = "mysql:host={$db_host};dbname={$db_name};charset=utf8mb4";
                $pdo = new PDO($dsn, $db_user, $db_pass, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                ]);

                if (!empty($password)) {
                    $hash = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare('UPDATE utilisateurs SET login = :login, password = :password, email = :email, firstname = :firstname, lastname = :lastname WHERE id = :id');
                    $stmt->execute([
                        ':login' => $login,
                        ':password' => $hash,
                        ':email' => $email,
                        ':firstname' => $firstname,
                        ':lastname' => $lastname,
                        ':id' => $user['id'],
                    ]);
                } else {
                    $stmt = $pdo->prepare('UPDATE utilisateurs SET login = :login, email = :email, firstname = :firstname, lastname = :lastname WHERE id = :id');
                    $stmt->execute([
                        ':login' => $login,
                        ':email' => $email,
                        ':firstname' => $firstname,
                        ':lastname' => $lastname,
                        ':id' => $user['id'],
                    ]);
                }

                // refresh session data
                $_SESSION['user']['login'] = $login;
                $_SESSION['user']['email'] = $email;
                $_SESSION['user']['firstname'] = $firstname;
                $_SESSION['user']['lastname'] = $lastname;
                $user = $_SESSION['user'];
                $success = 'Informations mises à jour.';
            } catch (PDOException $e) {
                $errors[] = 'Erreur base de données : ' . $e->getMessage();
            }
        }
    }
}

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Profil — Mon compte</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="modal">
    <div class="panel-signup">
      <h1>Profil</h1>

      <?php if (!empty($errors)): ?>
        <div class="msg err">
          <strong>Erreurs :</strong>
          <ul>
            <?php foreach($errors as $e): ?>
              <li><?= h($e) ?></li>
            <?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>

      <?php if ($success): ?>
        <div class="msg ok"><?= h($success) ?></div>
      <?php endif; ?>

      <form method="post" novalidate>
        <div class="row">
          <div style="flex:1">
            <label for="firstname">Prénom :</label>
            <input id="firstname" name="firstname" value="<?= h($user['firstname']) ?>" required>
          </div>
          <div style="flex:1">
            <label for="lastname">Nom :</label>
            <input id="lastname" name="lastname" value="<?= h($user['lastname']) ?>" required>
          </div>
        </div>

        <label for="login">Identifiant :</label>
        <input id="login" name="login" value="<?= h($user['login']) ?>" required>

                <label for="password">Mot de passe (laisser vide pour ne pas changer)</label>
                <div class="input-with-icon">
                  <button type="button" class="eye-toggle" aria-pressed="false" aria-label="Afficher ou masquer le mot de passe">
                    <!-- eye icon -->
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M12 5C7 5 2.73 8.11 1 12C2.73 15.89 7 19 12 19C17 19 21.27 15.89 23 12C21.27 8.11 17 5 12 5Z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
                  </button>
                  <input id="password" name="password" type="password">
                </div>

        <label for="email">Email :</label>
        <input id="email" name="email" type="email" value="<?= h($user['email']) ?>" required>

        <div style="margin-top:12px">
          <button type="submit" name="action" value="modify" class="btn-primary" style="width:100%;">Modifier</button>

          <div class="alt-action" style="margin-top:12px">
            <button type="submit" name="action" value="logout" class="alt-action-btn">Déconnecter</button>
          </div>
        </div>
      </form>
    </div>
  </div>
</body>
</html>
<script>
// password toggle for profile page
(function(){
  function toggleEye(btn){
    var pressed = btn.getAttribute('aria-pressed') === 'true';
    var input = btn.nextElementSibling;
    if (!input) return;
    if (pressed) {
      input.type = 'password';
      btn.setAttribute('aria-pressed','false');
    } else {
      input.type = 'text';
      btn.setAttribute('aria-pressed','true');
    }
  }
  document.querySelectorAll('.eye-toggle').forEach(function(btn){
    btn.addEventListener('click', function(){ toggleEye(btn); });
  });
})();
</script>
