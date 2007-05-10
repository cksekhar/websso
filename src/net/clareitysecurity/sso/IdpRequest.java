/*
 * IdpRequest.java
 *
 * This class encapsulates the logic to create a proper SAML 2.0
 * request to an Identity Provider to authenticate a user.
 */

package net.clareitysecurity.sso;

/**
 *
 * @author Paul Hethmon
 */
public class IdpRequest {
  
  private String
      issuerName,
      providerName,
      actionURL,
      relayState;
  
  public void setIssuerName(String newIssuerName) {
    issuerName = newIssuerName;
  }
  public String getIssuerName() {
    return issuerName;
  }
  
  /** Creates a new instance of IdpRequest */
  public IdpRequest() {
  }
  
}
