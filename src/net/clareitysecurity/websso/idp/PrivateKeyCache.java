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
    Security.addProvider(new BouncyCastleProvider());
  }
  
  public PrivateKey getPrivateKey() {
    RSAPrivateKey privateKey = null;
    KeyFactory keyFactory;
    PKCS8EncodedKeySpec privSpec;
    byte [] binaryKey;
    
    try {
      keyFactory = KeyFactory.getInstance("RSA");
      // decode private key
      binaryKey = Base64.decode( privateKeyEncoded );
      privSpec = new PKCS8EncodedKeySpec(binaryKey);
      privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
      return privateKey;
    } catch (NoSuchAlgorithmException nsae) {
      System.out.append("NoSuchAlgorithmException");
      nsae.printStackTrace();
      return null;
    } catch (InvalidKeySpecException ikse) {
      System.out.append("InvalidKeySpecException");
      ikse.printStackTrace();
      return null;
    }
//    if (privateKey != null) return privateKey;
    
/*            
    // Create the Java PrivateKey object
    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec( Base64.decode( privateKeyEncoded ) );
    // First try RSA encoded
    if (privateKey != null) return privateKey;
    
    try {
      keyFactory = KeyFactory.getInstance("DSA");
      privateKey = keyFactory.generatePrivate(x509EncodedKeySpec);
    } catch (NoSuchAlgorithmException nsae) {
      
    } catch (InvalidKeySpecException ikse) {
      
    }
*/
  }
}
