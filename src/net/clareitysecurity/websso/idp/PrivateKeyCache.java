/*
 * Copyright (C) 2007 National Association of REALTORS(R)
 *
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished
 * to do so, provided that the above copyright notice(s) and this
 * permission notice appear in all copies of the Software and that
 * both the above copyright notice(s) and this permission notice
 * appear in supporting documentation.
 */

/*
 * PrivateKeyCache.java
 *
 * Created on July 31, 2007, 6:53 PM
 *
 */

package net.clareitysecurity.websso.idp;

import org.opensaml.xml.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.*;
import java.security.*;
import java.security.interfaces.*;

/**
 * This class represents a private key used to sign SAML objects.
 *
 * @author Paul Hethmon
 */
public class PrivateKeyCache {
  
  private String privateKeyEncoded;
  private RSAPrivateKey privateKey;
  
  /*
   * Set the BASE64 encoded value of the private key.
   * @param s The BASE64 encoded value.
   */
  public void setPrivateKeyEncoded(String s) {
    privateKeyEncoded = s;
  }
  /*
   * Get the BASE64 encoded value of the private key.
   * @return The BASE64 encoded value.
   */
  public String getPrivateKeyEncoded() {
    return privateKeyEncoded;
  }
  
  /** Creates a new instance of PrivateKeyCache */
  public PrivateKeyCache() {
    privateKeyEncoded = null;
    privateKey = null;
//    Security.addProvider(new BouncyCastleProvider());
    Security.insertProviderAt(new BouncyCastleProvider(), 2);
}
  
  /*
   * Get the PrivateKey object for use in signing SAML objects.
   * @return The PrivateKey object.
   */
  public PrivateKey getPrivateKey() {
    //RSAPrivateKey privateKey = null;
    KeyFactory keyFactory;
    PKCS8EncodedKeySpec privSpec;
    byte [] binaryKey;
    
    // If we have created it already, just return it.
    if (privateKey != null) return privateKey;
    
    // Try to create the private key object and then return it.
    try {
      keyFactory = KeyFactory.getInstance("RSA");
      //System.out.println("provider = " + keyFactory.getProvider().toString() );
      // decode private key
      binaryKey = Base64.decode( privateKeyEncoded );
      privSpec = new PKCS8EncodedKeySpec(binaryKey);
      privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
      return privateKey;
    } catch (NoSuchAlgorithmException nsae) {
      //System.out.append("NoSuchAlgorithmException");
      nsae.printStackTrace();
      return null;
    } catch (InvalidKeySpecException ikse) {
      //System.out.append("InvalidKeySpecException");
      ikse.printStackTrace();
      return null;
    }
  }
  
  /*
   * Read the private key from a PEM encoded file and store the encoded
   * string in this object.
   * @param privateKeyFile The file containing the PEM encoded private key.
   */
  public void readPrivateKey(String privateKeyFile) throws java.io.FileNotFoundException, java.io.IOException {
    String
        line,
        encodedPrivateKey;
    
    encodedPrivateKey = "";
    // try to load a private key
    BufferedReader in = new BufferedReader(new FileReader(privateKeyFile));
    line = in.readLine();
    while (line != null) {
      encodedPrivateKey += line + "\r\n";
      line = in.readLine();
    }
    in.close();
    // Remove the markers from the data
    encodedPrivateKey = encodedPrivateKey.replace("-----BEGIN RSA PRIVATE KEY-----", "");
    encodedPrivateKey = encodedPrivateKey.replace("-----END RSA PRIVATE KEY-----", "");
    encodedPrivateKey = encodedPrivateKey.trim();
    // set the value in this object
    this.setPrivateKeyEncoded(encodedPrivateKey);
    
    return;
  }
}
