<?php
require_once '../config/database.php';
require_once '../helpers/JwtHelper.php';

class AuthController
{
    public static function register($name, $email, $password)
    {
        $db = new Database();
        $conn = $db->getConnection();

        $hashed_password = password_hash($password, PASSWORD_BCRYPT);

        $sql = "INSERT INTO users (name, email, password) VALUES ( :name, :email, :password )";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':nome', $name);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $hashed_password);
        $stmt->execute();

        return ["message" => "Usúario registrado com sucesso!"];
    }

    public static function login($email, $password)
    {
        $db = new Database();
        $conn = $db->getConnection();

        $sql = "SELECT id, password FROM users WHERE email = :email";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':email', $email);
        $stmt->execute();

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if($user && password_verify($password, $user['password'])){
            $token = JwtHelper::generateToken($user['id']);
            return ["token" => $token];
        }else{
            http_response_code(401);
            return ["message" => "Credenciais inválidas!"];
        }
    }
}
?>