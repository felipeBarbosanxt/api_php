<?php

class Database
{
    private $host = "localhost";
    private $db = "api";
    private $user = "root";
    private $password = "";
    private $conn;

    public function getConnection()
    {
        $this->conn = null;

        try {
            $this->conn = new PDO("mysql:host=". $this->host. ";dbname=". $this->db, $this->user, $this->password);
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            echo "Erro na conexão: ". $e->getMessage();
        }

        return $this->conn;
    }
}

?>