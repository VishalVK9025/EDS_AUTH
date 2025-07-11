package com.eds.auth.services;

import com.eds.auth.configs.JwtKeyLoader;
import com.eds.auth.dtos.LoginUserDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    @Autowired
    private JwtKeyLoader jwtKeyLoader;

    private Date extractExpiration(String token) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        return getClaimsFromToken(token, Claims::getExpiration);
    }

    public String getUsernameFromToken(String token) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        return getClaimsFromToken(token, Claims::getSubject);
    }

    public <T> T getClaimsFromToken(String token, Function<Claims, T> claimsResolver) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        return Jwts.parserBuilder().setSigningKey(jwtKeyLoader.getPrivateKey()).build().parseClaimsJws(token).getBody();
    }

    public Boolean validateToken(String token, LoginUserDto userDetails) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && isTokenExpired(token));
    }

    public String getRefKeyFromToken(String token) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        return getAllClaimsFromToken(token).get("username").toString();
    }

    private boolean isTokenExpired(String token) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        return !extractExpiration(token).before(new Date());
    }

    public boolean isTokenValid(String token, UserDetails userDetails) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername())) && isTokenExpired(token);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            LoginUserDto userDetails
    ) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(jwtKeyLoader.getPrivateKey())
                .compact();
    }

    public String generateToken(Map<String, Object> claims, LoginUserDto loginUserDto) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        return buildToken(claims, loginUserDto);
    }

//    private Key getSignInKey() {
//        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
//        return Keys.hmacShaKeyFor(keyBytes);
//    }

}