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
 * PostHandler.java
 *
 * Created on August 3, 2007, 11:03 PM
 *
 */

package net.clareitysecurity.websso.sp;

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
public class PostHandler extends AbstractHttpHandler {
  
  /** Creates a new instance of PostHandler */
  public PostHandler() throws org.opensaml.xml.ConfigurationException {
    super();
  }
  
  /*
   * Create a fully formed BASE64 representation of the SAML Request. The return value
   * is the value to place into the <b>SAMLRequest</b> form field submitted to the Idp.
   *
   * @return The BASE64 encoded SAMLRequest value.
   */
  public String createSAMLRequest() throws org.opensaml.xml.io.MarshallingException {
    AuthnRequest auth = buildAuthnRequest();
    return createSAMLRequest(auth);
  }
  /*
   * Create a fully formed BASE64 representation of the SAML Request. The return value
   * is the value to place into the <b>SAMLRequest</b> form field submitted to the Idp.
   * @param auth The AuthnRequest object to marshall and encode for POSTing
   * @return The BASE64 encoded SAMLRequest value.
   */
  public String createSAMLRequest(AuthnRequest auth) throws org.opensaml.xml.io.MarshallingException {
    String samlRequest;
    
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
