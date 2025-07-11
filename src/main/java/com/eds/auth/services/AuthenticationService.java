package com.eds.auth.services;

import com.eds.auth.dtos.AuthUserResp;
import com.eds.auth.dtos.LoginUserDto;
import com.eds.auth.dtos.RegisterUserDto;
import com.eds.auth.dtos.TokenDetails;
import com.eds.auth.entities.User;
import com.eds.auth.feignServices.EntitlementClient;
import com.eds.auth.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class AuthenticationService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private EntitlementClient entitlementClient;

    public User signup(RegisterUserDto input) {
        User user = new User();
        LocalDateTime now = LocalDateTime.now();
        user.setFullName(input.getFullName());
        user.setEmail(input.getEmail());
        user.setUsername(input.getUsername());
        user.setPassword(passwordEncoder.encode(input.getPassword()));
        user.setOriginalPassword(input.getPassword());
        user.setId("AUTH" + now.getYear() + now.getDayOfYear() + now.getSecond() + now.getNano());
        user.setEId((new Random().nextInt(9) +1) * 100000 + new Random().nextInt(90000) + 10000);
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());

        return userRepository.save(user);
    }

    public AuthUserResp authenticate(LoginUserDto input) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        Optional<User> byUsername = userRepository.findUserByUsernameAndOriginalPassword(input.getUsername(), input.getPassword());
        List<String> roleUser = null;
        String token = null;
        if (byUsername.isPresent()) {
            String userId = byUsername.get().getId();
            roleUser = entitlementClient.getRolesByUserId(userId);
            token = prepareJwtClaimAndGenerateToken(roleUser, input);
        } else {
            throw new BadCredentialsException("Invalid username or password");
        }
        return AuthUserResp.builder().username(input.getUsername()).jwtToken(token).roles(roleUser).build();
    }

    public boolean validateToken(String token) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        String refKey = jwtService.getRefKeyFromToken(token);
        User user = userRepository.findByUsername(refKey).orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + refKey));
        return jwtService.validateToken(token, LoginUserDto.builder().username(user.getUsername()).build());
    }

    public TokenDetails getTokenDetails(String token) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        String refKey = jwtService.getRefKeyFromToken(token);
        User user = userRepository.findByUsername(refKey).orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + refKey));
        return TokenDetails.builder().userId(user.getEId()).fullName(user.getFullName()).email(user.getEmail()).username(user.getUsername()).build();
    }

    public String prepareJwtClaimAndGenerateToken(List<String> roles, LoginUserDto loginUserDto) throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        Map<String, Object> jwtClaims = new HashMap<>();
        jwtClaims.put("roles", roles);
        jwtClaims.put("username", loginUserDto.getUsername());
        return jwtService.generateToken(jwtClaims, loginUserDto);
    }
}
