<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtHelper
{
    private static $secret_key = "NXT";
    private static $alg = "HS256";

    public static function generateTokem($userId)
    {
        $payload = [
            "iat" => time(),
            "exp" => time() + (60 * 60),
            "sub" => $userId
        ];
        
        return JWT::encode($payload, self::$secret_key, self::$alg);
    }

    public static function validateToken($token)
    {
        try {
            $decoded = JWT::decode($token, new Key(self::$secret_key, self::$alg));
            return $decoded->sub;
        } catch (Exception $e) {
            return null;
        }
    }
}


?>