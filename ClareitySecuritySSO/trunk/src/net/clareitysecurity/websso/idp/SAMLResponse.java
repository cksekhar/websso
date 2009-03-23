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
 * SAMLResponse.java
 *
 */

package net.clareitysecurity.websso.idp;

import java.io.StringWriter;
import java.util.Hashtable;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.KeyInfoImpl;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

/**
 *
 * @author Paul Hethmon
 */
public class SAMLResponse {
  
  /** Class logger. */
  private final Logger log = Logger.getLogger(SAMLResponse.class);
  
  private static boolean bootstrap = false;
  private static int bootcount = 0;
  private static int assertionConsumerServiceCount = 100;
  
  public static final String
      UNSPECIFIED = NameIDType.UNSPECIFIED,
      EMAIL = NameIDType.EMAIL,
      X509_SUBJECT = NameIDType.X509_SUBJECT,
      WIN_DOMAIN_QUALIFIED = NameIDType.WIN_DOMAIN_QUALIFIED,
      KERBEROS = NameIDType.KERBEROS,
      ENTITY = NameIDType.ENTITY,
      PERSISTENT = NameIDType.PERSISTENT,
      TRANSIENT = NameIDType.TRANSIENT,
      SUBJECT_URI_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
  
  private AuthnRequest
    authnRequest;
  private String
    issuerName,
    loginId,
    actionURL,
    responseXML,
    nameIdFormat;
  private PrivateKeyCache
    privateKeyCache;
  private PublicKeyCache
    publicKeyCache;
  private boolean
    signAssertion,
    simpleSAMLphp;
  private int
    minutes;
  private Hashtable
    assertionConsumerService;
  private String id = "acmeidp" + new DateTime().getMillis();
  
  /**
   * Add a URL and its index to the list of URLs to redirect the browser to.
   * @param idx The index at which to add this URL. Corresponds to the AssertionConsumerServiceIndex in the SAMLRequest.
   * @param url The fully qualified URL to redirect the browser to.
   */
    public void setAssertionConsumerService(int idx, String url) {
    if (assertionConsumerService == null) assertionConsumerService = new Hashtable(assertionConsumerServiceCount);
    assertionConsumerService.put(idx, url);
    log.debug("Adding [" + url + "] at index [" + idx + "]");
  }
  
  /**
   * Get the specified URL at the given index.
   * @param idx The index value to retrieve.
   * @return The URL if present. If the index is not valid, a null value is returned.
   */
  public String getAssertionConsumerService(int idx) {
    return (String) assertionConsumerService.get(idx);
  }
  /*
   * Set the number of minutes a Response will be valid for. Default value
   * is 5 minutes. Values less than zero will be set to 1 minute.
   * @param i The number of minutes.
   */
  public void setMinutes(int i) {
    minutes = i;
    if (minutes < 0) minutes = 1;
  }
  
  /*
   * Get the number of minutes the Response will be valid for.
   * @return The number of minutes.
   */
  public int getMinutes() {
    return minutes;
  }
  
  /**
   * Sets the unique identifier of the response. 
   * @param newId the unique identifier of the response
   */
  public void setId(String newId)
  {
      this.id = newId;
  }
  
  /**
   * Gets the unique identifier of the response. 
   * @return the unique identifier of the response
   */
  public String getId()
  {
     return this.id; 
  }
  
  /*
   * Set a boolean flag indicating you are talking to a PHP implementation
   * called simpleSAMLphp. It is broke and requires that the Response ID value
   * match exactly to the Reference URI value. What we do is prepend the Response
   * ID value with a # symbol. URI already has it since it is a fragment 
   * reference URI.
   * @param b true means to adjust our Response output to work with simpleSAMLphp
   */
  public void setSimpleSAMLphp(boolean b) {
    simpleSAMLphp = b;
  }
  /*
   * Get a boolean flag indicating you are talking to a PHP implementation
   * called simpleSAMLphp. It is broke and requires that the Response ID value
   * match exactly to the Reference URI value. What we do is prepend the Response
   * ID value with a # symbol. URI already has it since it is a fragment 
   * reference URI.
   * @return true means the Response output will be adjusted to work with simpleSAMLphp.
   */
  public boolean getSimpleSAMLphp() {
    return simpleSAMLphp;
  }
  
  public void setAuthnRequest(AuthnRequest newAuthnRequest) {
    authnRequest = newAuthnRequest;
  }
  public AuthnRequest getAuthnRequest() {
    return authnRequest;
  }
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
  public void setLoginId(String newLoginId) {
    loginId = newLoginId;
  }
  public String getLoginId() {
    return loginId;
  }
  public void setActionURL(String newActionURL) {
    actionURL = newActionURL;
  }
  public String getActionURL() {
    return actionURL;
  }
  public void setResponseXML(String newResponseXML) {
    responseXML = newResponseXML;
  }
  public String getResponseXML() {
    return responseXML;
  }
  public void setPrivateKeyCache(PrivateKeyCache newPrivateKeyCache) {
    privateKeyCache = newPrivateKeyCache;
  }
  public PrivateKeyCache getPrivateKeyCache() {
    return privateKeyCache;
  }
  public void setPublicKeyCache(PublicKeyCache newPublicKeyCache) {
    publicKeyCache = newPublicKeyCache;
  }
  public PublicKeyCache getPublicKeyCache() {
    return publicKeyCache;
  }
  public void setSignAssertion(boolean newSignAssertion) {
    signAssertion = newSignAssertion;
  }
  public boolean getSignAssertion() {
    return signAssertion;
  }
  public void setNameIdFormat(String newNameIdType) {
    nameIdFormat = newNameIdType;
  }
  public String getNameIdFormat() {
    return nameIdFormat;
  }
  /*
   * Create the SAMLResponse object for Idp usage.
   */
  public SAMLResponse() throws org.opensaml.xml.ConfigurationException {
    // do the bootstrap thing and make sure the library is happy
    if (bootstrap == false) {
      org.opensaml.DefaultBootstrap.bootstrap();
      bootstrap = true;
      if (log.isInfoEnabled()) {
        bootcount++;
        log.info("SAMLResponse.java - bootstrap has been called. [" + bootcount + "]");
      }
    }
    privateKeyCache = null;
    publicKeyCache = null;
    signAssertion = true;
    nameIdFormat = this.UNSPECIFIED;
    simpleSAMLphp = false;
    minutes = 5;
    assertionConsumerService = null;
  }
  
  public org.opensaml.saml2.core.Response getSuccessResponse() throws org.opensaml.xml.io.MarshallingException,
  	org.opensaml.xml.signature.SignatureException {
    org.opensaml.xml.signature.impl.SignatureImpl signature = null;
    org.opensaml.xml.security.x509.BasicX509Credential credential = null;
    org.opensaml.xml.signature.impl.KeyInfoImpl keyInfo = null;
    
    //System.out.println("Building Response object ...");
    // Use the OpenSAML Configuration singleton to get a builder factory object
    XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();
    
    // Set up the signing credentials if we have been given them.
    if (privateKeyCache != null) {
      //System.out.println("Configuring signature ...");
      try {
      org.opensaml.xml.signature.impl.SignatureBuilder signatureBuilder = new org.opensaml.xml.signature.impl.SignatureBuilder();
      
      signature = signatureBuilder.buildObject();
      credential = new org.opensaml.xml.security.x509.BasicX509Credential();
      // Set the private key used to sign the messages
      credential.setPrivateKey(privateKeyCache.getPrivateKey());
      // add the public key if we have it
      if (publicKeyCache != null) {
        credential.setPublicKey(publicKeyCache.getPublicKey());
        // Now add a KeyInfo section to the signature so we can send our public certificate in it
        KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder();
        keyInfo = (KeyInfoImpl) keyInfoBuilder.buildObject();
        //KeyInfoHelper.addPublicKey(keyInfo, publicKeyCache.getPublicKey());
        KeyInfoHelper.addCertificate(keyInfo, publicKeyCache.getX509Certificate());
        signature.setKeyInfo(keyInfo);
        if (log.isDebugEnabled()) log.debug("SAMLResponse.java - KeyInfo added to signature.");
      }
      signature.setSigningCredential(credential);
      signature.setSignatureAlgorithm( SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1 );
      signature.setCanonicalizationAlgorithm( SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS );
      } catch (Exception e) {
        //System.out.println("Caught exception configuring signature");
        e.printStackTrace();
      }
      //System.out.println("Finished Configuring signature ...");
    }

    // we must now build the SAMLResponse object to redirect the user back to the SP with
    // saml-core-2.0 has example of a response object, section 5.4.6, page 70
    ResponseBuilder rspBldr = (ResponseBuilder) builderFactory.getBuilder(org.opensaml.saml2.core.Response.DEFAULT_ELEMENT_NAME);
    org.opensaml.saml2.core.Response rsp = rspBldr.buildObject();
    
    // Check for the URL to return the browser to.
    if (authnRequest.getAssertionConsumerServiceURL() != null) {  // They sent a URL
      rsp.setDestination( authnRequest.getAssertionConsumerServiceURL() );
    } else if (authnRequest.getAssertionConsumerServiceIndex() > 0) {  // Specified by index instead
      String u = getAssertionConsumerService(authnRequest.getAssertionConsumerServiceIndex());
      if (u != null) {
        log.debug("Setting Destination to [" + u + "]");
        rsp.setDestination(u); // use the configured url at this index
      } else {
        log.debug("No Destination found. Using empty string.");
        rsp.setDestination(""); // nothing to use
      }
    } else {
        log.debug("No Index or URL found. Using empty string.");
        rsp.setDestination(""); // nothing to use
    }

    // Only a single ID value because they must match within the Response

    if (simpleSAMLphp == false) {
      rsp.setID(id);
    } else {
      rsp.setID("#" + id); // prepend with # to make us work with simpleSAMLphp
      if (log.isDebugEnabled()) log.debug("SAMLResponse.java simpleSAMLphp prepend set");
    }
    rsp.setInResponseTo( authnRequest.getID() );
    rsp.setVersion(SAMLVersion.VERSION_20);
    DateTime dt = new DateTime();
    rsp.setIssueInstant(dt);
    
    IssuerBuilder issuerBuilder = (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
    // Build the Issuer object
    Issuer issuer1 = issuerBuilder.buildObject();
    issuer1.setValue(issuerName);
    rsp.setIssuer(issuer1);
    
    // Set the successful status
    StatusBuilder statusBuilder = (StatusBuilder) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
    Status status = (Status) statusBuilder.buildObject();
    // Now construct the StatusCode itself
    StatusCodeBuilder statusCodeBuilder = (StatusCodeBuilder) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
    StatusCode statusCode = statusCodeBuilder.buildObject(); //(StatusCode.SUCCESS_URI, StatusCode.DEFAULT_ELEMENT_LOCAL_NAME, null);
    // Set the value
    statusCode.setValue(StatusCode.SUCCESS_URI);
    status.setStatusCode(statusCode);
    // Add it to the SAMLResponse object
    rsp.setStatus(status);
    
    // Add an Assertion of this authenticated user
    AssertionBuilder assertionBuilder = (AssertionBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
    Assertion assertion = assertionBuilder.buildObject();
    // Add the issue instance to the Assertion
    assertion.setIssueInstant(dt);
    assertion.setVersion(SAMLVersion.VERSION_20);
    assertion.setID(id);
    // Add the Issuer to the Assertion
    // Build the Issuer object
    Issuer issuer2 = issuerBuilder.buildObject();
    issuer2.setValue(issuerName);
    assertion.setIssuer(issuer2);
    
    // Now add a subject to the response
    SubjectBuilder subjectBuilder = (SubjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
    Subject subject = subjectBuilder.buildObject();
    // Create the NameID
    NameIDBuilder nidb = (NameIDBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
    NameID nid = nidb.buildObject();
    nid.setFormat( getNameIdFormat() );
    nid.setValue(loginId);
    // Add the NameID to the subject
    subject.setNameID(nid);
    
    // Create the SubjectConfirmation
    SubjectConfirmationBuilder subjectConfirmationBuilder =
      (SubjectConfirmationBuilder) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
    SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
    subjectConfirmation.setMethod( this.SUBJECT_URI_BEARER );
    
    // Now the Conditions that are allowed
    ConditionsBuilder conditionsBuilder = (ConditionsBuilder) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
    Conditions conditions = conditionsBuilder.buildObject();
    // Build the starting time window value, we allow now less 1 minute
    DateTime notBefore, notAfter;
    notBefore = dt.minus( 1000 * 10 );  // 10 seconds in the past is all we allow.
    conditions.setNotBefore(notBefore);
    // Allow up to 5 minutes in the future
    notAfter = dt.plus( 1000 * 60 * this.getMinutes() ); // minutes into the future defaults to 5
    conditions.setNotOnOrAfter(notAfter);
    assertion.setConditions(conditions);
    
    // Create the SubjectConfirmationData element
    SubjectConfirmationDataBuilder subjectConfirmationDataBuilder =
      (SubjectConfirmationDataBuilder) builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
    SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
    subjectConfirmationData.setRecipient(authnRequest.getAssertionConsumerServiceURL());
    subjectConfirmationData.setNotOnOrAfter(notAfter);
    subjectConfirmationData.setInResponseTo(authnRequest.getID());
    // Add this to the SubjectConfirmation
    subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
    // Add the SubjectConfirmation to the Subject
    subject.getSubjectConfirmations().add(subjectConfirmation);
    
    // Add the Subject to the Assertion
    assertion.setSubject(subject);
    
    // Build the AuthnContextClassRef
    AuthnContextClassRefBuilder authnContextClassRefBuilder =
      (AuthnContextClassRefBuilder) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
    AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
    authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
    
    // Build the AuthnContext
    AuthnContextBuilder authnContextBuilder = (AuthnContextBuilder) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
    AuthnContext authnContext = authnContextBuilder.buildObject();
    authnContext.setAuthnContextClassRef(authnContextClassRef);
    
    // Build the AuthnStatement itself
    AuthnStatementBuilder authnStatementBuilder = (AuthnStatementBuilder) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
    AuthnStatement authnStatement = authnStatementBuilder.buildObject();
    authnStatement.setAuthnContext(authnContext);
    authnStatement.setAuthnInstant(dt);
    // Add the AuthnStatement to the Assertion
    assertion.getAuthnStatements().add(authnStatement);
    
    // Finally add the Assertion to our SAMLResponse
    rsp.getAssertions().add(assertion);
    
    // Sign the assertion if asked to do so.
    org.opensaml.common.impl.SAMLObjectContentReference socr;
    if ((signAssertion == true) && (signature != null)) {
/*      
      //System.out.println("Signing assertion ...");
      socr = new org.opensaml.common.impl.SAMLObjectContentReference(assertion);
      socr.getTransforms().clear();
      boolean b = socr.getTransforms().add(SignatureConstants.TRANSFORM_ENVELOPED_SIGNATURE);
      //System.out.println("add transform: [" + SignatureConstants.TRANSFORM_ENVELOPED_SIGNATURE + "] " + b);
      b = socr.getTransforms().add(SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
      //System.out.println("add transform: [" + SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS + "] " + b);
      //signature.getContentReferences().add(socr);
      //signature.
*/
      assertion.setSignature(signature);
      // Get the marshaller factory
      MarshallerFactory marshallerFactory = org.opensaml.Configuration.getMarshallerFactory();
      Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
      try {
        // By marshalling the assertion, we will create the XML so that the signing will have something to sign
        marshaller.marshall(assertion);
      } catch (MarshallingException e) {
        e.printStackTrace();
      }
      // Now sign it
      org.opensaml.xml.signature.Signer.signObject(signature);
      //System.out.print("Assertion is now signed ...");
    }
    
    return rsp;
  }
  
  /*
   * Create a successful SAML Response message as XML.
   * @return The SAML message as XML.
   */
  public String createSuccessResponse() throws org.opensaml.xml.io.MarshallingException,
  org.opensaml.xml.signature.SignatureException {
    org.opensaml.saml2.core.Response rsp = getSuccessResponse();
    return createSuccessResponse(rsp);
  }
  
  /*
   * Create a successful SAML Response message as XML.
   * @param rsp The Response object to create the XML from.
   * @return The SAML message as XML.
   */
  public String createSuccessResponse(org.opensaml.saml2.core.Response rsp) throws org.opensaml.xml.io.MarshallingException {
    // Now we must build our representation to put into the html form to be submitted to the idp
    Marshaller marshaller = org.opensaml.Configuration.getMarshallerFactory().getMarshaller(rsp);
    Element authDOM = marshaller.marshall(rsp);
    StringWriter rspWrt = new StringWriter();
    XMLHelper.writeNode(authDOM, rspWrt);
    responseXML = rspWrt.toString();
    
    String samlResponse = new String(Base64.encodeBytes(responseXML.getBytes(), Base64.DONT_BREAK_LINES));
    
    // Set the URL to where we resolved the destination to go to.
    setActionURL(rsp.getDestination());
    
    return samlResponse;
  }
}
