package com.eds.auth.controllers;

import com.eds.auth.dtos.AuthUserResp;
import com.eds.auth.dtos.LoginUserDto;
import com.eds.auth.dtos.RegisterUserDto;
import com.eds.auth.dtos.TokenDetails;
import com.eds.auth.entities.User;
import com.eds.auth.services.AuthenticationService;
import com.eds.auth.services.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

@RestController
public class AuthenticationController {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<User> register(@RequestBody RegisterUserDto registerUserDto) {
        User registeredUser = authenticationService.signup(registerUserDto);
        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthUserResp> authenticate(@RequestBody LoginUserDto loginUserDto) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        AuthUserResp authenticatedUser = authenticationService.authenticate(loginUserDto);
        return ResponseEntity.ok(authenticatedUser);
    }

    @GetMapping("/validate")
    public boolean validateToken(@RequestParam String token) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        return authenticationService.validateToken(token);
    }

    @GetMapping("/getTokenDetails")
    public TokenDetails getTokenDetails(@RequestParam String token) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        return authenticationService.getTokenDetails(token);
    }
}