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
 * HttpPost.java
 *
 * This class implements the logic necessary to decode and validate a SAML Request
 * received from a Service Provider for the HTTP POST binding.
 *
 */

package net.clareitysecurity.websso.idp;

import org.opensaml.Configuration;
import org.opensaml.common.binding.BindingException;
import org.opensaml.saml2.binding.*;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.io.*;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.util.Base64;
import javax.servlet.http.HttpServletRequest;

/**
 *
 * @author Paul Hethmon
 */
public class HttpPost {

  /** HTTP request param name for SAML request. */
  public static final String REQUEST_PARAM = "SAMLRequest";

  /** HTTP request param name for SAML response. */
  public static final String RESPONSE_PARAM = "SAMLResponse";

  /** HTTP request param name for relay state. */
  public static final String RELAY_STATE_PARAM = "RelayState";
  
  private String
    xmlSAMLRequest,
    relayState;
  
  public void setXMLSAMLRequest(String newXMLSAMLRequest) {
    xmlSAMLRequest = newXMLSAMLRequest;
  }
  public String getXMLSAMLRequest() {
    return xmlSAMLRequest;
  }
  public void setRelayState(String newRelayState) {
    relayState = newRelayState;
  }
  public String getRelayState() {
    return relayState;
  }
  
  /*
   * Create the HttpPost object for Idp usage.
   */
  public HttpPost() throws org.opensaml.xml.ConfigurationException {
    // do the bootstrap thing and make sure the library is happy
    org.opensaml.DefaultBootstrap.bootstrap();
  }
  
  public AuthnRequest decodeSAMLRequest(HttpServletRequest request) throws BindingException {
    AuthnRequest samlRequest = null;
    
    HTTPPostDecoder decode = new HTTPPostDecoder();
    decode.setParserPool( new ParserPool() );
    decode.setRequest(request);
    decode.decode();

    // Save the SAML Request as a SAML Object
    samlRequest = (AuthnRequest) decode.getSAMLMessage();
    // Now save it as a String in case we need it later
    byte [] b = Base64.decode(request.getParameter(REQUEST_PARAM));
    xmlSAMLRequest = new String(b);

    // Now save the Relay State as an encoded value. We only return this
    // to the SP, so no need to Base64 decode it.
    relayState = decode.getRelayState();
    
    return samlRequest;
  }
}
