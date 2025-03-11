<?php
require_once '../helpers/JwtHelper.php';

class AuthMiddleware
{
    public static function verifyToken()
    {
        $headers = getallheaders();
        if(!isset($headers['Authorization'])){
            http_response_code(401);
            echo json_encode(["message" => "Token ausente"]);
            exit();
        }

        $token = str_replace("Bearer ", "", $headers['Authorizatoion']);
        $userId = JwtHelper::validateToken($token);

        if(!$userId){
            http_response_code(401);
            echo json_encode(["message" => "Token invalido"]);
            exit();
        }

        return $userId;
    }
}


?>