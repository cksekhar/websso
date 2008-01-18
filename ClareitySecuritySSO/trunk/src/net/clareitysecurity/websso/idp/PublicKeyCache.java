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
 * PublicKeyCache.java
 *
 * Created on 15 January 2008
 *
 */

package net.clareitysecurity.websso.idp;

import org.opensaml.xml.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.*;
import java.security.*;
import java.security.interfaces.*;

/**
 * This class represents a public key used to sign SAML objects.
 *
 * @author Paul Hethmon
 */
public class PublicKeyCache {
  
  private String publicKeyEncoded;
  private RSAPublicKey publicKey;
  
  /*
   * Set the BASE64 encoded value of the public key.
   * @param s The BASE64 encoded value.
   */
  public void setPublicKeyEncoded(String s) {
    publicKeyEncoded = s;
  }
  /*
   * Get the BASE64 encoded value of the public key.
   * @return The BASE64 encoded value.
   */
  public String getPublicKeyEncoded() {
    return publicKeyEncoded;
  }
  
  /** Creates a new instance of PublicKeyCache */
  public PublicKeyCache() {
    publicKeyEncoded = null;
    publicKey = null;
//    Security.addProvider(new BouncyCastleProvider());
    Security.insertProviderAt(new BouncyCastleProvider(), 2);
}
  
  /*
   * Get the PublicKey object for use in signing SAML objects.
   * @return The PublicKey object.
   */
  public PublicKey getPublicKey() {
    //RSAPublicKey publicKey = null;
    KeyFactory keyFactory;
    X509EncodedKeySpec pubSpec;
    byte [] binaryKey;
    
    // If we have created it already, just return it.
    if (publicKey != null) return publicKey;
    
    // Try to create the public key object and then return it.
    try {
      keyFactory = KeyFactory.getInstance("RSA");
      //System.out.println("provider = " + keyFactory.getProvider().toString() );
      // decode public key
//      binaryKey = Base64.decode( publicKeyEncoded );
//      pubSpec = new X509EncodedKeySpec(binaryKey);
      
      pubSpec = new X509EncodedKeySpec(publicKeyEncoded.getBytes());

      publicKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);
      return publicKey;
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
   * Read the public key from a PEM encoded file and store the encoded
   * string in this object.
   * @param publicKeyFile An InputStream containing the PEM encoded public key.
   */
  public void readPublicKey(InputStream publicKeyFile) throws java.io.FileNotFoundException, java.io.IOException {
    BufferedReader in = new BufferedReader(new InputStreamReader(publicKeyFile));
    readPublicKey(in);
  }
  /*
   * Read the public key from a PEM encoded file and store the encoded
   * string in this object.
   * @param publicKeyFile The file containing the PEM encoded public key.
   */
  public void readPublicKey(String publicKeyFile) throws java.io.FileNotFoundException, java.io.IOException {
    // try to load a public key
    BufferedReader in = new BufferedReader(new FileReader(publicKeyFile));
    readPublicKey(in);
  }  
  /*
   * Read the public key from a PEM encoded file and store the encoded
   * string in this object.
   * @param publicKeyFile A BufferedReader containing the PEM encoded public key.
   */
  public void readPublicKey(BufferedReader publicKeyFile) throws java.io.FileNotFoundException, java.io.IOException {
    String
        line,
        encodedPublicKey;
    
    encodedPublicKey = "";
    
    line = publicKeyFile.readLine();
    while (line != null) {
      encodedPublicKey += line + "\r\n";
      line = publicKeyFile.readLine();
    }
    publicKeyFile.close();
    // Remove the markers from the data
    encodedPublicKey = encodedPublicKey.replace("-----BEGIN CERTIFICATE-----", "");
    encodedPublicKey = encodedPublicKey.replace("-----END CERTIFICATE-----", "");
    encodedPublicKey = encodedPublicKey.trim();
    // set the value in this object
    this.setPublicKeyEncoded(encodedPublicKey);
    
    return;
  }
}
