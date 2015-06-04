/**
 * 
 */
package com.ideamoment.saml.idp.shiro.authninfo;

import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.ByteSource;


/**
 * @author Chinakite
 *
 */
public class IdeaAuthenticationInfo extends SimpleAuthenticationInfo {
    
    protected String userId;
    
    /**
     * @return the userId
     */
    public String getUserId() {
        return userId;
    }
    
    /**
     * @param userId the userId to set
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }
    
    /**
     * Default no-argument constructor.
     */
    public IdeaAuthenticationInfo() {
    }

    /**
     * Constructor that takes in a single 'primary' principal of the account and its corresponding credentials,
     * associated with the specified realm.
     * <p/>
     * This is a convenience constructor and will construct a {@link PrincipalCollection PrincipalCollection} based
     * on the {@code principal} and {@code realmName} argument.
     *
     * @param principal   the 'primary' principal associated with the specified realm.
     * @param credentials the credentials that verify the given principal.
     * @param realmName   the realm from where the principal and credentials were acquired.
     */
    public IdeaAuthenticationInfo(Object principal, Object credentials, String realmName, String userId) {
        this.principals = new SimplePrincipalCollection(principal, realmName);
        this.credentials = credentials;
        this.userId = userId;
    }

    /**
     * Constructor that takes in a single 'primary' principal of the account, its corresponding hashed credentials,
     * the salt used to hash the credentials, and the name of the realm to associate with the principals.
     * <p/>
     * This is a convenience constructor and will construct a {@link PrincipalCollection PrincipalCollection} based
     * on the <code>principal</code> and <code>realmName</code> argument.
     *
     * @param principal         the 'primary' principal associated with the specified realm.
     * @param hashedCredentials the hashed credentials that verify the given principal.
     * @param credentialsSalt   the salt used when hashing the given hashedCredentials
     * @param realmName         the realm from where the principal and credentials were acquired.
     * @see org.apache.shiro.authc.credential.HashedCredentialsMatcher HashedCredentialsMatcher
     * @since 1.1
     */
    public IdeaAuthenticationInfo(Object principal, Object hashedCredentials, ByteSource credentialsSalt, String realmName, String userId) {
        this.principals = new SimplePrincipalCollection(principal, realmName);
        this.credentials = hashedCredentials;
        this.credentialsSalt = credentialsSalt;
        this.userId = userId;
    }

    /**
     * Constructor that takes in an account's identifying principal(s) and its corresponding credentials that verify
     * the principals.
     *
     * @param principals  a Realm's account's identifying principal(s)
     * @param credentials the accounts corresponding principals that verify the principals.
     */
    public IdeaAuthenticationInfo(PrincipalCollection principals, Object credentials, String userId) {
        this.principals = new SimplePrincipalCollection(principals);
        this.credentials = credentials;
        this.userId = userId;
    }

    /**
     * Constructor that takes in an account's identifying principal(s), hashed credentials used to verify the
     * principals, and the salt used when hashing the credentials.
     *
     * @param principals        a Realm's account's identifying principal(s)
     * @param hashedCredentials the hashed credentials that verify the principals.
     * @param credentialsSalt   the salt used when hashing the hashedCredentials.
     * @see org.apache.shiro.authc.credential.HashedCredentialsMatcher HashedCredentialsMatcher
     * @since 1.1
     */
    public IdeaAuthenticationInfo(PrincipalCollection principals, Object hashedCredentials, ByteSource credentialsSalt, String userId) {
        this.principals = new SimplePrincipalCollection(principals);
        this.credentials = hashedCredentials;
        this.credentialsSalt = credentialsSalt;
        this.userId = userId;
    }
}
