/*
 * HTTPPOST.java
 *
 * This class encapsulates the logic to create a proper SAML 2.0
 * request to an Identity Provider to authenticate a user. It implements
 * the logic necessary to use the HTTP POST binding.
 */

package net.clareitysecurity.websso;

import java.io.StringWriter;
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
public class HTTPPOST {
  
  private String
      issuerName,
      providerName,
      actionURL,
      assertionConsumerServiceURL;
  
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
   * Create the HTTPPOST object.
   */
  public HTTPPOST() throws org.opensaml.xml.ConfigurationException {
    // do the bootstrap thing and make sure the library is happy
    org.opensaml.DefaultBootstrap.bootstrap();
  }
  
  /*
   * Create a fully formed BASE64 representation of the SAML Request. The return value
   * is the value to place into the <b>SAMLRequest</b> form field submitted to the Idp.
   *
   * @return The BASE64 encoded SAMLRequest value.
   */
  public String createSAMLRequest() throws org.opensaml.xml.io.MarshallingException {
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

    // Now do a special base64 encoding of our XML. Normal base64 has line length limitations.
    samlRequest = new String(Base64.encodeBytes(messageXML.getBytes(), Base64.DONT_BREAK_LINES));

    return samlRequest;
  }
  
  /*
   * Create the BASE64 encoded value for RelayState. The return value is the value to
   * place into the <b>RelayState</b> form field submitted to the Idp.
   *
   * @return The BASE64 encoded RelayState value.
   */
  public String createRelayState(String uncodedRelayState) {
    return ( new String(Base64.encodeBytes(uncodedRelayState.getBytes(), Base64.DONT_BREAK_LINES)) );
  }
}
