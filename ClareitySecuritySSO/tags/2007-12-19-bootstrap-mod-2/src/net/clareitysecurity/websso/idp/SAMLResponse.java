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
import org.joda.time.DateTime;
import org.apache.log4j.Logger;

import org.apache.xml.security.signature.XMLSignature;

import org.opensaml.*;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.*;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.*;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.io.*;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.signature.*;

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
  private boolean
    signAssertion;
  
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
        log.info("SAMLResponse.java (line 147) bootstrap has been called. [" + bootcount + "]");
      }
    }
    privateKeyCache = null;
    signAssertion = true;
    nameIdFormat = this.UNSPECIFIED;
  }
  
  public org.opensaml.saml2.core.Response getSuccessResponse() throws org.opensaml.xml.io.MarshallingException {
    org.opensaml.xml.signature.impl.SignatureImpl signature = null;
    org.opensaml.xml.security.x509.BasicX509Credential credential = null;
    
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
      credential.setPrivateKey(privateKeyCache.getPrivateKey());
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
    
    rsp.setDestination( authnRequest.getAssertionConsumerServiceURL() );
    DateTime ts = new DateTime();
    rsp.setID("acmeidp" + ts.getMillis());
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
    ts = new DateTime();
    assertion.setID("acmeidp" + ts.getMillis());
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
    notBefore = dt.minus( 1000 * 60 );
    conditions.setNotBefore(notBefore);
    // Allow up to 5 minutes in the future
    notAfter = dt.plus( 1000 * 60 * 5 );
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
      //System.out.println("Signing assertion ...");
      socr = new org.opensaml.common.impl.SAMLObjectContentReference(assertion);
      socr.getTransforms().clear();
      boolean b = socr.getTransforms().add(SignatureConstants.TRANSFORM_ENVELOPED_SIGNATURE);
      //System.out.println("add transform: [" + SignatureConstants.TRANSFORM_ENVELOPED_SIGNATURE + "] " + b);
      b = socr.getTransforms().add(SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
      //System.out.println("add transform: [" + SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS + "] " + b);
      signature.getContentReferences().add(socr);
      //signature.
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
   * Create a succesful SAML Response message as XML.
   * @return The SAML message as XML.
   */
  public String createSuccessResponse() throws org.opensaml.xml.io.MarshallingException {
    org.opensaml.saml2.core.Response rsp = getSuccessResponse();
    return createSuccessResponse(rsp);
  }
  
  /*
   * Create a succesful SAML Response message as XML.
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
    
    setActionURL(authnRequest.getAssertionConsumerServiceURL());
    
    return samlResponse;
  }
}
