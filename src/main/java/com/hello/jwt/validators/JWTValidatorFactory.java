package com.hello.jwt.validators;

import com.hello.jwt.JWTValidator;

public class JWTValidatorFactory {

    private JWTValidatorFactory() {}

    public static JWTValidator getInstance(Validator validator) {
        if(validator == Validator.SYMMETRIC) {
            return new JWTSymmetricValidator();
        } else if (validator == Validator.ASYMMETRIC) {
            return new JWTAsymmetricValidator();
        }
        throw new UnsupportedOperationException("Validator not supported.");
    }
}
