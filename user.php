<?php

class User
{
    private $id;
    public $login;
    public $email;
    public $firstname;
    public $lastname;
    
    /** @var mysqli|null */
    private $conn = null;
    /** @var bool */
    private $connected = false;

    /**
     * Constructeur optionnel : fournit une connexion mysqli
     * @param mysqli|null $mysqli
     */
    public function __construct($mysqli = null)
    {
        if ($mysqli instanceof mysqli) {
            $this->conn = $mysqli;
        }
    }

    /**
     * Permet d'assigner la connexion mysqli après création
     * @param mysqli $mysqli
     * @return void
     */
    public function setConnection($mysqli)
    {
        if ($mysqli instanceof mysqli) {
            $this->conn = $mysqli;
        }
    }

    private function ensureConnection()
    {
        return ($this->conn instanceof mysqli);
    }

    public function register($login, $password, $email, $firstname, $lastname)
    {
        if (!$this->ensureConnection()) {
            return false;
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->conn->prepare("INSERT INTO utilisateurs (login, password, email, firstname, lastname) VALUES (?, ?, ?, ?, ?)");
        if (!$stmt) {
            return false;
        }
        $stmt->bind_param('sssss', $login, $hash, $email, $firstname, $lastname);
        if (!$stmt->execute()) {
            $stmt->close();
            return false;
        }
        $this->id = $this->conn->insert_id;
        $stmt->close();

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

        $stmt = $this->conn->prepare("SELECT id, login, password, email, firstname, lastname FROM utilisateurs WHERE login = ? LIMIT 1");
        if (!$stmt) {
            return false;
        }
        $stmt->bind_param('s', $login);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

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

        $stmt = $this->conn->prepare("DELETE FROM utilisateurs WHERE id = ?");
        if (!$stmt) {
            return false;
        }
        $stmt->bind_param('i', $this->id);
        $ok = $stmt->execute();
        $stmt->close();

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
            $stmt = $this->conn->prepare("UPDATE utilisateurs SET login = ?, password = ?, email = ?, firstname = ?, lastname = ? WHERE id = ?");
            if (!$stmt) return false;
            $stmt->bind_param('sssssi', $login, $hash, $email, $firstname, $lastname, $this->id);
        } else {
            $stmt = $this->conn->prepare("UPDATE utilisateurs SET login = ?, email = ?, firstname = ?, lastname = ? WHERE id = ?");
            if (!$stmt) return false;
            $stmt->bind_param('ssssi', $login, $email, $firstname, $lastname, $this->id);
        }

        $ok = $stmt->execute();
        $stmt->close();

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
