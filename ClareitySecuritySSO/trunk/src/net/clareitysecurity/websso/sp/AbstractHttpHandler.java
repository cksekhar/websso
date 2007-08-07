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
 * AbstractHttpHandler.java
 *
 * This class encapsulates the logic to create a proper SAML 2.0
 * request to an Identity Provider to authenticate a user. It implements
 * the base logic necessary for HTTP methods of SSO.
 */

package net.clareitysecurity.websso.sp;

//import java.io.StringWriter;
import org.joda.time.DateTime;

import org.opensaml.*;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.*;
import org.opensaml.xml.io.*;
import org.opensaml.xml.util.*;
import org.opensaml.common.xml.SAMLConstants;

import org.w3c.dom.Element;

/**
 *
 * @author Paul Hethmon
 */
public abstract class AbstractHttpHandler {
  
  public static final String
    REDIRECT_BINDING = org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder.BINDING_URI,
    POST_BINDING = org.opensaml.saml2.binding.encoding.HTTPPostEncoder.BINDING_URI;
  
  protected String
      issuerName,
      providerName,
      actionURL,
      assertionConsumerServiceURL,
      bindingUriFormat;
  protected boolean
      forceReAuthentication;
  
  /*
   * The IssuerName is the unique identifier value of your server.
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
   * The ActionURL is the fully formed URL where the SAML Request will be posted
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
  /*
   * Set whether you want the IdP to re-authenticate the user. Default value is false.
   * @param newForceReAuthentication If true, the IdP will require the user to re-authenticate.
   */
  public void setForceReAuthentication(boolean newForceReAuthentication) {
    forceReAuthentication = true;
  }
  /*
   * Get the value of whether you want the IdP to re-authenticate the user. Default value
   * is false.
   * @return The current value (true means force re-authentication)
   */
  public boolean getForceReAuthentication() {
    return forceReAuthentication;
  }
  /*
   * Set the protocol binding format. This is how the Idp returns the SAML Response
   * to the SP. Supported is Redirect and POST.
   */
  public void setBindindUriFormat(String newBindingUriFormat) {
    bindingUriFormat = newBindingUriFormat;
  }
  /*
   * Get the current value of the binding format. This is how the Idp returns the
   * SAML Response to the SP.
   */
  public String getBindingUriFormat() {
    return bindingUriFormat;
  }
  
  /*
   * Create the AbstractHttpHandler object for SP usage.
   */
  public AbstractHttpHandler() throws org.opensaml.xml.ConfigurationException {
    // do the bootstrap thing and make sure the library is happy
    org.opensaml.DefaultBootstrap.bootstrap();
    forceReAuthentication = false;
    this.bindingUriFormat = this.POST_BINDING;
  }
  
  public AuthnRequestImpl buildAuthnRequest() {
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
    auth.setProtocolBinding( getBindingUriFormat() );
    // Only add the parameter if it is true.
    if (forceReAuthentication == true) {
      auth.setForceAuthn(forceReAuthentication);
    }
    //auth.setAssertionConsumerServiceIndex(0);
    //auth.setAttributeConsumingServiceIndex(0);
    auth.setVersion(org.opensaml.common.SAMLVersion.VERSION_20);
    DateTime dt = new DateTime();
    auth.setIssueInstant(dt);
    auth.setID("acmemls:" + dt.getMillis());

    return auth;
  }
  
}
