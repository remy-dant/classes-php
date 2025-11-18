<?php

class Userpdo
{
    private $id;
    public $login;
    public $email;
    public $firstname;
    public $lastname;

    /** @var PDO|null */
    private $pdo = null;
    /** @var bool */
    private $connected = false;

    /**
     * Constructeur optionnel : fournit une instance PDO
     * @param PDO|null $pdo
     */
    public function __construct($pdo = null)
    {
        if ($pdo instanceof PDO) {
            $this->pdo = $pdo;
        }
    }

    /**
     * Assigne la connexion PDO après création
     * @param PDO $pdo
     * @return void
     */
    public function setConnection(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    private function ensureConnection()
    {
        return ($this->pdo instanceof PDO);
    }

    public function register($login, $password, $email, $firstname, $lastname)
    {
        if (!$this->ensureConnection()) {
            return false;
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $sql = "INSERT INTO utilisateurs (login, password, email, firstname, lastname) VALUES (:login, :password, :email, :firstname, :lastname)";
        $stmt = $this->pdo->prepare($sql);
        $ok = $stmt->execute([
            ':login' => $login,
            ':password' => $hash,
            ':email' => $email,
            ':firstname' => $firstname,
            ':lastname' => $lastname,
        ]);

        if (!$ok) {
            return false;
        }

        $this->id = (int)$this->pdo->lastInsertId();
        $this->login = $login;
        $this->email = $email;
        $this->firstname = $firstname;
        $this->lastname = $lastname;
        $this->connected = true;

        return $this->getAllInfos();
    }

    public function connect($login, $password)
    {
        if (!$this->ensureConnection()) {
            return false;
        }

        $sql = "SELECT id, login, password, email, firstname, lastname FROM utilisateurs WHERE login = :login LIMIT 1";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':login' => $login]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            return false;
        }

        if (!password_verify($password, $user['password'])) {
            return false;
        }

        $this->id = (int)$user['id'];
        $this->login = $user['login'];
        $this->email = $user['email'];
        $this->firstname = $user['firstname'];
        $this->lastname = $user['lastname'];
        $this->connected = true;

        return true;
    }

    public function disconnect()
    {
        $this->id = null;
        $this->login = null;
        $this->email = null;
        $this->firstname = null;
        $this->lastname = null;
        $this->connected = false;
    }

    public function delete()
    {
        if (!$this->ensureConnection() || !$this->connected || empty($this->id)) {
            return false;
        }

        $sql = "DELETE FROM utilisateurs WHERE id = :id";
        $stmt = $this->pdo->prepare($sql);
        $ok = $stmt->execute([':id' => $this->id]);

        $this->disconnect();
        return $ok;
    }

    public function update($login, $password, $email, $firstname, $lastname)
    {
        if (!$this->ensureConnection() || !$this->connected || empty($this->id)) {
            return false;
        }

        if (!empty($password)) {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $sql = "UPDATE utilisateurs SET login = :login, password = :password, email = :email, firstname = :firstname, lastname = :lastname WHERE id = :id";
            $params = [
                ':login' => $login,
                ':password' => $hash,
                ':email' => $email,
                ':firstname' => $firstname,
                ':lastname' => $lastname,
                ':id' => $this->id,
            ];
        } else {
            $sql = "UPDATE utilisateurs SET login = :login, email = :email, firstname = :firstname, lastname = :lastname WHERE id = :id";
            $params = [
                ':login' => $login,
                ':email' => $email,
                ':firstname' => $firstname,
                ':lastname' => $lastname,
                ':id' => $this->id,
            ];
        }

        $stmt = $this->pdo->prepare($sql);
        $ok = $stmt->execute($params);

        if ($ok) {
            $this->login = $login;
            $this->email = $email;
            $this->firstname = $firstname;
            $this->lastname = $lastname;
        }

        return $ok;
    }

    public function isConnected()
    {
        return (bool)$this->connected;
    }

    public function getAllInfos()
    {
        return [
            'id' => $this->id,
            'login' => $this->login,
            'email' => $this->email,
            'firstname' => $this->firstname,
            'lastname' => $this->lastname,
        ];
    }

    public function getLogin()
    {
        return $this->login;
    }

    public function getEmail()
    {
        return $this->email;
    }

    public function getFirstname()
    {
        return $this->firstname;
    }

    public function getLastname()
    {
        return $this->lastname;
    }
}
