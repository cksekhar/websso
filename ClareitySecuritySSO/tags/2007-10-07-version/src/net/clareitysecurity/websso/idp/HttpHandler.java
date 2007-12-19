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
 * HttpHandler.java
 *
 *
 */

package net.clareitysecurity.websso.idp;

import org.apache.log4j.Logger;
import org.opensaml.Configuration;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.core.*;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.io.*;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.util.Base64;
import javax.servlet.http.HttpServletRequest;

/**
 * This class implements the logic necessary to decode and validate a SAML Request
 * received from a Service Provider for the HTTP POST or redirect binding.
 *
 * @author Paul Hethmon
 */
public class HttpHandler {

  /** Class logger. */
  private final Logger log = Logger.getLogger(HttpHandler.class);
  
  /** HTTP request param name for SAML request. */
  public static final String REQUEST_PARAM = "SAMLRequest";

  /** HTTP request param name for SAML response. */
  public static final String RESPONSE_PARAM = "SAMLResponse";

  /** HTTP request param name for relay state. */
  public static final String RELAY_STATE_PARAM = "RelayState";
  
  protected String
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
   * Create the HttpHandler object for Idp usage.
   */
  public HttpHandler() throws org.opensaml.xml.ConfigurationException {
    // do the bootstrap thing and make sure the library is happy
    org.opensaml.DefaultBootstrap.bootstrap();
  }
  
  public AuthnRequest decodeSAMLRequest(HttpServletRequest request) 
    throws BindingException, org.opensaml.ws.security.SecurityPolicyException, java.util.zip.DataFormatException, 
      org.opensaml.ws.message.MessageException
  {
    AuthnRequest samlRequest = null;
    
    System.out.println("HttpHandler:decodeSAMLRequest");
    if (log.isDebugEnabled()) {
      log.debug("HttpHandler:decodeSAMLRequest");
      }
    // First see whether we have a GET or POST so we know where to look for the data
    if (request.getMethod().equalsIgnoreCase("GET") == true) {
      System.out.println("HttpHandler:decodeSAMLRequest - Found GET");
      if (log.isDebugEnabled()) {
        log.debug("HttpHandler:decodeSAMLRequest - Found GET");
        }
      HTTPRedirectDeflateDecoder decode = new HTTPRedirectDeflateDecoder(new BasicParserPool());
      HttpServletRequestAdapter adapter = new HttpServletRequestAdapter(request);
      BasicSAMLMessageContext context = new BasicSAMLMessageContext();
      context.setInboundMessageTransport(adapter);
      decode.decode(context);
      // Save the SAML Request as a SAML Object
      samlRequest = (AuthnRequest) context.getInboundMessage();
      //samlRequest = (AuthnRequest) decode.getSAMLMessage();
      // Now save it as a String in case we need it later
      byte [] b = Base64.decode(request.getParameter(REQUEST_PARAM));
      byte [] i = new byte[ b.length * 3];
      xmlSAMLRequest = new String(b);
      java.util.zip.Inflater inflater = new java.util.zip.Inflater(true);
      inflater.setInput(b);
      inflater.inflate(i);
      xmlSAMLRequest = new String(i);
      // Now save the Relay State as an encoded value. We only return this
      // to the SP, so no need to Base64 decode it.
      relayState = adapter.getParameterValue(this.RELAY_STATE_PARAM);
    } else if (request.getMethod().equalsIgnoreCase("POST") == true) {
      System.out.println("HttpHandler:decodeSAMLRequest - Found POST");
      if (log.isDebugEnabled()) {
        log.debug("HttpHandler:decodeSAMLRequest - Found POST");
        }
      HTTPPostDecoder decode = new HTTPPostDecoder( new BasicParserPool() );
      HttpServletRequestAdapter adapter = new HttpServletRequestAdapter(request);
      BasicSAMLMessageContext context = new BasicSAMLMessageContext();
      context.setInboundMessageTransport(adapter);
      decode.decode(context);
      // Save the SAML Request as a SAML Object
      samlRequest = (AuthnRequest) context.getInboundMessage();
      // Now save it as a String in case we need it later
      byte [] b = Base64.decode(request.getParameter(REQUEST_PARAM));
      xmlSAMLRequest = new String(b);

      // Now save the Relay State as an encoded value. We only return this
      // to the SP, so no need to Base64 decode it.
      relayState = adapter.getParameterValue(this.RELAY_STATE_PARAM);
    } else {
      // bad things happened here
    }

    return samlRequest;
  }
}
