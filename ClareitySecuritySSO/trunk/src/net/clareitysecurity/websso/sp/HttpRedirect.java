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
 * HttpRedirect.java
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
public class HttpRedirect {
  
  private String
      issuerName,
      providerName,
      actionURL,
      assertionConsumerServiceURL,
      relayState;
  
  /*
   * The IssuerName is the unique identifier value of your application.
   */
  public void setIssuerName(String newIssuerName) {
    issuerName = newIssuerName;
  }
  /*
   * Get the current value of the IssuerName.
   */
  public String getIssuerName() {
    return issuerName;
  }
  /*
   * The ProviderName is the human readable name of your application for use
   * by the Identity Provider.
   */
  public void setProviderName(String newProviderName) {
    providerName = newProviderName;
  }
  /*
   * Get the current value of the ProviderName.
   */
  public String getProviderName() {
    return providerName;
  }
  /*
   * The ActionURL is the fully formed URL where the SAML Request will be redirected
   * to. It should be of the form <b>http://www.acmeidp.com/recv-authnrequest.jsp</b>.
   */
  public void setActionURL(String newActionURL) {
    actionURL = newActionURL;
  }
  /*
   * Get the current value of the ActionURL.
   */
  public String getActionURL() {
    return actionURL;
  }
  /*
   * The AssertionConsumerServiceURL is the URL location that the Idp will return
   * the Assertion to once the user is authenticated. It should be a fully
   * formed URL such as <b>http://www.acmemls.com/recv-saml.jsp</b>.
   */
  public void setAssertionConsumerServiceURL(String newAssertionConsumerServiceURL) {
    assertionConsumerServiceURL = newAssertionConsumerServiceURL;
  }
  /*
   * Get the current value of the AssertionConsumerServiceURL.
   */
  public String getAssertionConsumerServiceURL() {
    return assertionConsumerServiceURL;
  }
  public void setRelayState(String newRelayState) {
    relayState = newRelayState;
  }
  public String getRelayState() {
    return relayState;
  }
  
  /*
   * Create the HttpRedirect object for SP usage.
   */
  public HttpRedirect() throws org.opensaml.xml.ConfigurationException {
    // do the bootstrap thing and make sure the library is happy
    org.opensaml.DefaultBootstrap.bootstrap();
  }
  
  /*
   * Create a fully formed DEFLATEd and BASE64 representation of the SAML Request. The return value
   * is the value to place in the redirect including the URL and parameters.
   *
   * @return The full redirect URL.
   */
  public void sendSAMLRedirect(HttpServletResponse response) throws org.opensaml.xml.io.MarshallingException, BindingException, IOException {
    String samlRequest;
    
    // Use the OpenSAML Configuration singleton to get a builder factory object
    XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();
    // First get a builder for AuthnRequest
    AuthnRequestBuilder arb = (AuthnRequestBuilder) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
    // And one for Issuer
    IssuerBuilder ib = (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
    // And one for Subject
    SubjectBuilder sb = (SubjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
    // build an AuthnRequest object
    AuthnRequestImpl auth = (AuthnRequestImpl) arb.buildObject();
    // Build the Issuer object
    Issuer newIssuer = ib.buildObject();
    newIssuer.setValue(issuerName);
    auth.setIssuer(newIssuer);
    auth.setProviderName(providerName);
    auth.setAssertionConsumerServiceURL(assertionConsumerServiceURL);
    auth.setDestination(actionURL);
    //auth.setAssertionConsumerServiceIndex(0);
    //auth.setAttributeConsumingServiceIndex(0);
    auth.setVersion(org.opensaml.common.SAMLVersion.VERSION_20);
    DateTime dt = new DateTime();
    auth.setIssueInstant(dt);
    auth.setID("acmemls:" + dt.getMillis());

    Marshaller marshaller = org.opensaml.Configuration.getMarshallerFactory().getMarshaller(auth);
    Element authDOM = marshaller.marshall(auth);
    // We use a StringWriter to produce our XML output. This gets us XML where
    // the encoding is UTF-8
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
    
      /*
      ByteArrayOutputStream messageOut = new ByteArrayOutputStream();
      Base64.OutputStream b64Out = new Base64.OutputStream(messageOut);
      Deflater deflater = new Deflater(Deflater.DEFLATED, true);
      DeflaterOutputStream deflaterStream = new DeflaterOutputStream(b64Out, deflater);
      deflaterStream.write(messageStr.getBytes());
      deflaterStream.close();
      return messageOut.toByteArray();
    } catch (IOException e) {
      throw new BindingException("Unable to DEFLATE and Base64 encode SAML message", e);
    }
       **/
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
