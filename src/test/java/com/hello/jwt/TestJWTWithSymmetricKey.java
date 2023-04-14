package com.hello.jwt;

import com.hello.jwt.validators.JWTValidatorFactory;
import com.hello.jwt.validators.Validator;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

public class TestJWTWithSymmetricKey {

    private static final Map<String, Object> GENERAL_CLAIMS = new HashMap<String, Object>(){{
        put("name", "Thoughtworks");
        put("email", "tw@thoughtworks.com");
        put("isAdmin", true);
    }};

    @Test
    public void generateAndValidateToken() {
        String jwt = JWTGenerator.generate(Validator.SYMMETRIC, GENERAL_CLAIMS);
        Assertions.assertNotNull(jwt);
        Assertions.assertTrue(JWTValidatorFactory.getInstance(Validator.SYMMETRIC).isValid(jwt));
    }

    @Test
    public void generateAndValidateExpiredToken() throws InterruptedException {
        String jwt = JWTGenerator.generate(Validator.SYMMETRIC, GENERAL_CLAIMS);
        Assertions.assertNotNull(jwt);
        Thread.sleep(6000);
        Assertions.assertFalse(JWTValidatorFactory.getInstance(Validator.SYMMETRIC).isValid(jwt));
    }

    @Test
    public void checkClaims() {
        String jwt = JWTGenerator.generate(Validator.SYMMETRIC, GENERAL_CLAIMS);
        Assertions.assertNotNull(jwt);
        Assertions.assertTrue(JWTValidatorFactory.getInstance(Validator.SYMMETRIC).isValid(jwt));

        Claims claims = JWTValidatorFactory.getInstance(Validator.SYMMETRIC).claims(jwt);
        Assertions.assertNotNull(claims);
        Assertions.assertEquals(claims.get("name"), GENERAL_CLAIMS.get("name"));
    }
}
