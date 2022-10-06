package com.twed.jwt;

import io.jsonwebtoken.Claims;

public interface JWTValidator {

    boolean isValid(String jwt);

    Claims claims(String jwt);
}
