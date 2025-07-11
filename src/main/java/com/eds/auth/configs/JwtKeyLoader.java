package com.eds.auth.configs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

@Component
public class JwtKeyLoader {
    @Value("${server.ssl.key-store}")
    private String keyStorePath;

    @Value("${server.ssl.key-store-password}")
    private String keyStorePassword;

    @Value("${server.ssl.key-alias}")
    private String keyAlias;

    @Value("${server.ssl.key-store-type}")
    private String keyStoreType;

    public PrivateKey getPrivateKey() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
        FileInputStream fis = new FileInputStream(keyStorePath);
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(fis, keyStorePassword.toCharArray());
        KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(keyStorePassword.toCharArray());
//        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, passwordProtection);
        return (PrivateKey) keyStore.getKey(keyAlias, keyStorePassword.toCharArray());
//        return keyEntry.getPrivateKey();
    }
}
