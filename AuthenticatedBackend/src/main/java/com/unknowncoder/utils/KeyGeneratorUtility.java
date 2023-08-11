package com.unknowncoder.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeyGeneratorUtility {

    public static KeyPair generateRsaKey() {
        // we need rsa key pair to generate jwt token , to generate then , encrypt them, encode them whatever
        // generate encode and decode our jwts ,
        KeyPair keyPair;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA"); // this is going to get us an instance
            // of a key generator that can go ahead and create RSA keypairs for us above, initialize below with 2048 bit
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException();
        }
        return keyPair;
        // with this we will need a model to actually store the key pair inside we cant just use keypair
        // we will need something called an RSA key properties , go ahead and make a new class inside utils
    }
}
