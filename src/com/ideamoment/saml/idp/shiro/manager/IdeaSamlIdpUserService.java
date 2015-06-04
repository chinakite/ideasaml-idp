/**
 * 
 */
package com.ideamoment.saml.idp.shiro.manager;

import com.ideamoment.saml.model.SamlUser;


/**
 * @author Chinakite
 *
 */
public interface IdeaSamlIdpUserService {
    /**
     * 根据用户Id查找User
     * 
     * @param id
     * @return
     */
    public SamlUser findUser(String id);
}
