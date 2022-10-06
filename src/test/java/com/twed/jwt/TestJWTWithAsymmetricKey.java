package com.twed.jwt;

import com.twed.jwt.validators.JWTValidatorFactory;
import com.twed.jwt.validators.Validator;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

public class TestJWTWithAsymmetricKey {

    private static final Map<String, Object> GENERAL_CLAIMS = new HashMap<String, Object>(){{
        put("name", "Thoughtworks");
        put("email", "tw@thoughtworks.com");
        put("isAdmin", true);
    }};

    @Test
    public void generateAndValidateToken() {
        String jwt = JWTGenerator.generate(Validator.ASYMMETRIC, GENERAL_CLAIMS);
        Assertions.assertNotNull(jwt);
        Assertions.assertTrue(JWTValidatorFactory.getInstance(Validator.ASYMMETRIC).isValid(jwt));
    }

    @Test
    public void generateAndValidateExpiredToken() throws InterruptedException {
        String jwt = JWTGenerator.generate(Validator.ASYMMETRIC, GENERAL_CLAIMS);
        Assertions.assertNotNull(jwt);
        Thread.sleep(6000);
        Assertions.assertFalse(JWTValidatorFactory.getInstance(Validator.ASYMMETRIC).isValid(jwt));
    }

    @Test
    public void checkClaims() throws InterruptedException {
        String jwt = JWTGenerator.generate(Validator.ASYMMETRIC, GENERAL_CLAIMS);
        Assertions.assertNotNull(jwt);
        Assertions.assertTrue(JWTValidatorFactory.getInstance(Validator.ASYMMETRIC).isValid(jwt));

        Claims claims = JWTValidatorFactory.getInstance(Validator.ASYMMETRIC).claims(jwt);
        Assertions.assertNotNull(claims);
        Assertions.assertEquals(claims.get("name"), GENERAL_CLAIMS.get("name"));
    }
}
