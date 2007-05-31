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
 * Response.java
 *
 */

package net.clareitysecurity.websso.idp;

import java.io.StringWriter;
import org.joda.time.DateTime;

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

import org.w3c.dom.Element;


/**
 *
 * @author Paul Hethmon
 */
public class Response {
  
  private AuthnRequest
    authnRequest;
  private String
    issuerName,
    loginId,
    actionURL,
    responseXML;
  
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
  
  /*
   * Create the Response object for Idp usage.
   */
  public Response() throws org.opensaml.xml.ConfigurationException {
    // do the bootstrap thing and make sure the library is happy
    org.opensaml.DefaultBootstrap.bootstrap();
  }
  
  public String createSuccessResponse() throws org.opensaml.xml.io.MarshallingException {
    // Use the OpenSAML Configuration singleton to get a builder factory object
    XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();
    
    // we must now build the Response object to redirect the user back to the SP with
    // saml-core-2.0 has example of a response object, section 5.4.6, page 70
    ResponseBuilder rspBldr = (ResponseBuilder) builderFactory.getBuilder(org.opensaml.saml2.core.Response.DEFAULT_ELEMENT_NAME);
    org.opensaml.saml2.core.Response rsp = rspBldr.buildObject();
    
    rsp.setDestination( authnRequest.getAssertionConsumerServiceURL() );
    DateTime ts = new DateTime();
    rsp.setID("acmeidp:" + ts.getMillis());
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
    // Add it to the Response object
    rsp.setStatus(status);
    
    // Add an Assertion of this authenticated user
    AssertionBuilder assertionBuilder = (AssertionBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
    Assertion assertion = assertionBuilder.buildObject();
    // Add the issue instance to the Assertion
    assertion.setIssueInstant(dt);
    assertion.setVersion(SAMLVersion.VERSION_20);
    ts = new DateTime();
    assertion.setID("acmeidp:" + ts.getMillis());
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
    nid.setFormat(NameIDType.UNSPECIFIED);
    nid.setValue(loginId);
    // Add the NameID to the subject
    subject.setNameID(nid);
    
    // Create the SubjectConfirmation
    SubjectConfirmationBuilder subjectConfirmationBuilder =
      (SubjectConfirmationBuilder) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
    SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
    
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
    //assertion.setConditions(conditions);
    
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
    
    // Finally add the Assertion to our Response
    rsp.getAssertions().add(assertion);
    
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
