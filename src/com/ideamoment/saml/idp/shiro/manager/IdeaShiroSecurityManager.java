/**
 * 
 */
package com.ideamoment.saml.idp.shiro.manager;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;

import com.ideamoment.saml.idp.shiro.authninfo.IdeaAuthenticationInfo;
import com.ideamoment.saml.model.SamlUser;


/**
 * @author Chinakite
 *
 */
public class IdeaShiroSecurityManager extends DefaultWebSecurityManager {

    private IdeaSamlIdpUserService userService;
    
    /**
     * @return the userService
     */
    public IdeaSamlIdpUserService getUserService() {
        return userService;
    }
    
    /**
     * @param userService the userService to set
     */
    public void setUserService(IdeaSamlIdpUserService userService) {
        this.userService = userService;
    }
    
    /* (non-Javadoc)
     * @see org.apache.shiro.mgt.DefaultSecurityManager#onSuccessfulLogin(org.apache.shiro.authc.AuthenticationToken, org.apache.shiro.authc.AuthenticationInfo, org.apache.shiro.subject.Subject)
     */
    @Override
    protected void onSuccessfulLogin(AuthenticationToken token,
                                     AuthenticationInfo info,
                                     Subject subject) {

        String userId = ((IdeaAuthenticationInfo)info).getUserId();
        SamlUser user = userService.findUser(userId);
        subject.getSession().setAttribute("userId", userId);
        subject.getSession().setAttribute("user", user);
        
        super.onSuccessfulLogin(token, info, subject);
        
        
    }
    
}
