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
 * RecvResponse.java
 *
 * Created on August 3, 2007, 11:40 PM
 *
 */

package net.clareitysecurity.websso.sp;

import java.io.StringWriter;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;

import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.common.binding.BasicSAMLMessageContext;

//import org.opensaml.ws.message.BaseMessageContext;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;

import org.opensaml.xml.io.*;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signature;

import org.w3c.dom.Element;

/**
 * This class handles receiving a SAML Response object from an IdP and
 * processing it to determine whether the user is valid.
 *
 * @author Paul Hethmon
 */
public class RecvResponse {
  
  /** Class logger. */
  private final Logger log = Logger.getLogger(RecvResponse.class);
  
  private static boolean bootstrap = false;
  private static int bootcount = 0;
  
  /** HTTP request param name for SAML request. */
  public static final String REQUEST_PARAM = "SAMLRequest";

  /** HTTP request param name for SAML response. */
  public static final String RESPONSE_PARAM = "SAMLResponse";

  /** HTTP request param name for relay state. */
  public static final String RELAY_STATE_PARAM = "RelayState";
  
  protected String
      relayState,
      loginId,
      responseXML;
  protected SignatureValidator
      signatureValidator;
  
  /*
   * Set the value of the relay state.
   * @param newRelayState The new value to set the relay state to.
   */
  public void setRelayState(String newRelayState) {
    relayState = newRelayState;
  }
  /*
   * Get the value of the relay state as returned by the IdP.
   * @return The current relay state value.
   */
  public String getRelayState() {
    return relayState;
  }
  /*
   * Set the value of the authenticated user.
   * @param newLoginId The authenticated id to set the login id to.
   */
  public void setLoginId(String newLoginId) {
    loginId = newLoginId;
  }
  /*
   * Get the value of the authenticated user as returned by the IdP.
   * @return The authenticated login id.
   */
  public String getLoginId() {
    return loginId;
  }
  /*
   * Set the value of the Response XML.
   * @param newResponseXML The value to set the Response XML to.
   */
  public void setResponseXML(String newResponseXML) {
    responseXML = newResponseXML;
  }
  /*
   * Get the value of the Response XML as returned by the IdP.
   * @return The Response as XML.
   */
  public String getResponseXML() {
    return responseXML;
  }
  /*
   * Set the SignatureValidator object value. The SignatureValidator is used to
   * validate the signatures of signed SAML objects from the IdP.
   * @param newSignatureValidator The new SignatureValidator object.
   */
  public void setSignatureValidator(SignatureValidator newSignatureValidator) {
    signatureValidator = newSignatureValidator;
  }
  
  /** Creates a new instance of RecvResponse */
  public RecvResponse() throws org.opensaml.xml.ConfigurationException {
    // do the bootstrap thing and make sure the library is happy
    if (bootstrap == false) {
      org.opensaml.DefaultBootstrap.bootstrap();
      bootstrap = true;
      if (log.isInfoEnabled()) {
        bootcount++;
        log.info("RecvResponse.java (line 136) bootstrap has been called. [" + bootcount + "]");
      }
    }
  }
  
  public void processRequest(HttpServletRequest request) 
    throws org.opensaml.xml.io.MarshallingException, org.opensaml.common.binding.BindingException, 
      org.opensaml.ws.security.SecurityPolicyException, org.opensaml.xml.validation.ValidationException,
      org.opensaml.ws.message.MessageException
  {
    java.util.List<Assertion> assertionsList;
    
    HTTPPostDecoder decode = new HTTPPostDecoder( new BasicParserPool() );
    HttpServletRequestAdapter adapter = new HttpServletRequestAdapter(request);
    BasicSAMLMessageContext context = new BasicSAMLMessageContext();
    context.setInboundMessageTransport(adapter);
    decode.decode(context);
    relayState = adapter.getParameterValue(this.RELAY_STATE_PARAM); // decode.getRelayState();
    // Only decode the relay state if there is one
    if ((relayState != null) && (relayState.equalsIgnoreCase("") == false)) {
      relayState = new String(Base64.decode(relayState));
    }
    
    // Use the OpenSAML Configuration singleton to get a builder factory object
    XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();
    // Get a Response object
    ResponseBuilder rspBldr = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
    Response rsp = rspBldr.buildObject();
    rsp = (Response) context.getInboundMessage();
    
    // Look in the SAML Response to pull out the Subject information
    Assertion assertion;
    // Get the list of assertions
    assertionsList = rsp.getAssertions();
    // Make sure at least one is present
    if (assertionsList.size() > 0) {
      // Get the first one only
      assertion = (Assertion)assertionsList.get(0);
      // Now we must validate the signature of the assertion
      Signature signatureToValidate;
      signatureToValidate = assertion.getSignature();
      // Now try to validate. Throw exception if not valid.
      signatureValidator.validate(signatureToValidate);
      
      // Pull the Subject data
      Subject subject = assertion.getSubject();
      // Now we have the NameID element
      NameID nameId = subject.getNameID();
      setLoginId( nameId.getValue() );
    }
    
    Marshaller marshaller = org.opensaml.Configuration.getMarshallerFactory().getMarshaller(rsp);
    Element authDOM = marshaller.marshall(rsp);
    StringWriter rspWrt = new StringWriter();
    XMLHelper.writeNode(authDOM, rspWrt);
    setResponseXML( rspWrt.toString() );
    
    return;
  }
}
