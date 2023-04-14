package com.hello.jwt;

import com.hello.jwt.validators.Validator;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

public class JWTGenerator {

   private static final String SECRET_KEY = "ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz0123456789";

   private static final KeyPair RSA_KEY_PAIR = initializeRSAKeyPair();

   public static String generate(Validator validator, Map<String, Object> claims) {
      if(validator == Validator.SYMMETRIC) {
         return generateWithSymmetricKey(claims);
      } else if (validator == Validator.ASYMMETRIC) {
         return generateWithAsymmetricKey(claims);
      }
      throw new UnsupportedOperationException("Validator is not supported.");
   }

   private static String generateWithSymmetricKey(Map<String, Object> claims) {
      byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
      SecretKey secretKey = Keys.hmacShaKeyFor(keyBytes);
      return Jwts.builder()
              .addClaims(claims)
              .setSubject("jwt-symmetric-key-demo")
              .setId(UUID.randomUUID().toString())
              .setIssuedAt(Date.from(Instant.now()))
              .setExpiration(Date.from(Instant.now().plus(5L, ChronoUnit.SECONDS)))
              .signWith(secretKey)
              .compact();
   }

   private static String generateWithAsymmetricKey(Map<String, Object> claims) {
      return Jwts.builder()
              .addClaims(claims)
              .setSubject("jwt-asymmetric-key-demo")
              .setId(UUID.randomUUID().toString())
              .setIssuedAt(Date.from(Instant.now()))
              .setExpiration(Date.from(Instant.now().plus(5L, ChronoUnit.SECONDS)))
              .signWith(RSA_KEY_PAIR.getPrivate(), SignatureAlgorithm.RS256)
              .compact();
   }

   private static KeyPair initializeRSAKeyPair() {
      try {
         KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
         keyPairGenerator.initialize(2048);
         return keyPairGenerator.generateKeyPair();
      } catch(Exception e) {
         throw new IllegalStateException("RSA key generation failed!");
      }
   }

   public static PublicKey getPublicKey() {
      return RSA_KEY_PAIR.getPublic();
   }
}
