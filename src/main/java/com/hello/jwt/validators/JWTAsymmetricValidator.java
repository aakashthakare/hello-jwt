package com.hello.jwt.validators;

import com.hello.jwt.JWTGenerator;
import com.hello.jwt.JWTValidator;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;

class JWTAsymmetricValidator implements JWTValidator {

    public boolean isValid(String jwtFromRequest) {
        try {
            Jwts.parserBuilder().setSigningKey(JWTGenerator.getPublicKey()).build().parse(jwtFromRequest);
            return true;
        } catch(ExpiredJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
            return false;
        }
    }

    public Claims claims(String jwtFromRequest) {
        Jws<Claims> jws = Jwts.parserBuilder().setSigningKey(JWTGenerator.getPublicKey()).build().parseClaimsJws(jwtFromRequest);
        return jws.getBody();
    }
}
