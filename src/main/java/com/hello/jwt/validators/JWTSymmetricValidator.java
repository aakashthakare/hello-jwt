package com.hello.jwt.validators;

import com.hello.jwt.JWTValidator;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

public class JWTSymmetricValidator implements JWTValidator {

    private static final String SECRET_KEY = "ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz0123456789";

    public boolean isValid(String jwtFromRequest) {
        Key key = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), SignatureAlgorithm.HS256.getJcaName());
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parse(jwtFromRequest);
            return true;
        } catch(ExpiredJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
            return false;
        }
    }

    public Claims claims(String jwtFromRequest) {
        Key key = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), SignatureAlgorithm.HS256.getJcaName());
        Jws<Claims> jws = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwtFromRequest);
        return jws.getBody();
    }
}
