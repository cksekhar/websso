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
 * RedirectHandler.java
 *
 * This class encapsulates the logic to create a proper SAML 2.0
 * request to an Identity Provider to authenticate a user. It implements
 * the logic necessary to use the HTTP redirect binding.
 */

package net.clareitysecurity.websso.sp;

import java.io.StringWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.List;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;

import org.opensaml.*;
import org.opensaml.common.binding.BindingException;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.*;
import org.opensaml.xml.io.*;
import org.opensaml.xml.util.*;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.util.URLBuilder;

import org.w3c.dom.Element;

/**
 *
 * @author Paul Hethmon
 */
public class RedirectHandler extends AbstractHttpHandler {

  protected String
    relayState;
  
  public void setRelayState(String newRelayState) {
    relayState = newRelayState;
  }
  public String getRelayState() {
    return relayState;
  }
  
  /*
   * Create the RedirectHandler object for SP usage.
   */
  public RedirectHandler() throws org.opensaml.xml.ConfigurationException {
    super();
  }
  
  /*
   * Create a fully formed DEFLATEd and BASE64 representation of the SAML Request. This
   * method submits the response to the client directly.
   *
   */
  public void sendSAMLRedirect(HttpServletResponse response) throws org.opensaml.xml.io.MarshallingException, BindingException, IOException {
    String samlRequest;
    
    // build an AuthnRequest object
    AuthnRequestImpl auth = buildAuthnRequest();
    auth.setProtocolBinding( org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder.BINDING_URI );

    // Now we must marshall the object for the transfer over the wire.
    Marshaller marshaller = org.opensaml.Configuration.getMarshallerFactory().getMarshaller(auth);
    Element authDOM = marshaller.marshall(auth);
    // We use a StringWriter to produce our XML output. This gets us XML where
    // the encoding is UTF-8. We must have UTF-8 or bad things happen.
    StringWriter rspWrt = new StringWriter();
    XMLHelper.writeNode(authDOM, rspWrt);
    String messageXML = rspWrt.toString();

    String encodedMessage = deflateAndBase64Encode(messageXML);

    String redirectURL = buildRedirectURL(encodedMessage);

    response.setCharacterEncoding("UTF-8");
    response.addHeader("Cache-control", "no-cache, no-store");
    response.addHeader("Pragma", "no-cache");
    response.sendRedirect(redirectURL);
    
    return;
  }
  
  /*
   * Create a fully formed SAML Request.
   *
   * @return The SAML Request as XML.
   */
  public String createSAMLRedirect() throws org.opensaml.xml.io.MarshallingException, BindingException, IOException {
    String samlRequest;
    
    // build an AuthnRequest object
    AuthnRequestImpl auth = buildAuthnRequest();
    auth.setProtocolBinding( org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder.BINDING_URI );

    // Now we must marshall the object for the transfer over the wire.
    Marshaller marshaller = org.opensaml.Configuration.getMarshallerFactory().getMarshaller(auth);
    Element authDOM = marshaller.marshall(auth);
    // We use a StringWriter to produce our XML output. This gets us XML where
    // the encoding is UTF-8. We must have UTF-8 or bad things happen.
    StringWriter rspWrt = new StringWriter();
    XMLHelper.writeNode(authDOM, rspWrt);
    String messageXML = rspWrt.toString();

    return messageXML;
  }
  
  /**
   * DEFLATE (RFC1951) compresses the given SAML message.
   *
   * @param message SAML message
   *
   * @return DEFLATE compressed message
   *
   * @throws BindingException thrown if there is a problem compressing the message
   */
  protected String deflateAndBase64Encode(String message) {
    int compressedLength;
    byte [] data = new byte[message.length()];
    Deflater deflater = new Deflater(Deflater.DEFLATED, true);
    deflater.setInput(message.getBytes());
    deflater.finish();
    compressedLength = deflater.deflate(data);
    return ( Base64.encodeBytes(data, 0, compressedLength) );
  }
  
  /**
   * Builds the URL to redirect the client to.
   *
   * @param message base64 encoded SAML message
   *
   * @return URL to redirect client to
   *
   */
  protected String buildRedirectURL(String message) {
    URLBuilder urlBuilder = new URLBuilder(getActionURL());
    
    List<Pair<String, String>> queryParams = urlBuilder.getQueryParams();
    queryParams.clear();
    
    queryParams.add(new Pair<String, String>("SAMLRequest", message));
    
    if (!DatatypeHelper.isEmpty(getRelayState())) {
      queryParams.add(new Pair<String, String>("RelayState", getRelayState()));
    }
    
    return urlBuilder.buildURL();
  }
  
}
