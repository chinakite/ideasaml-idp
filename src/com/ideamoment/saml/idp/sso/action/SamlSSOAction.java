/**
 * 
 */
package com.ideamoment.saml.idp.sso.action;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import com.ideamoment.saml.IdeaSamlException;
import com.ideamoment.saml.SamlDecoder;
import com.ideamoment.saml.SamlLogoutRequest;
import com.ideamoment.saml.SamlLogoutResponse;
import com.ideamoment.saml.SamlRequest;
import com.ideamoment.saml.SamlResponse;
import com.ideamoment.saml.model.SamlUser;


/**
 * @author Chinakite
 *
 */
@Controller
public class SamlSSOAction {
    
    private static Logger logger = LoggerFactory.getLogger(SamlSSOAction.class);
    
    /**
     * 跳转到登录页面
     * 
     * @return
     */
    @RequestMapping(value="/toSSOLogin", method=RequestMethod.POST)
    public ModelAndView toLogin(String samlRequest, String relayState) {
        HashMap<String, Object> model = new HashMap<String, Object>();
        model.put("samlRequest", samlRequest);
        model.put("relayState", relayState);
        
        return new ModelAndView("/page/sso/ssologin.jsp", model);
    }
    
    /**
     * 用户登录
     * 
     * @return
     * @throws UnsupportedEncodingException 
     */
    @RequestMapping(value="/ssologin", method=RequestMethod.POST)
    public ModelAndView ssologin(String uniqueKey, String password, String samlRequest, String relayState) throws UnsupportedEncodingException {
        UsernamePasswordToken token = new UsernamePasswordToken(uniqueKey, password);
        
        Subject subject = SecurityUtils.getSubject();
        subject.login(token);
        
        SamlDecoder decoder = new SamlDecoder(samlRequest);
        samlRequest = decoder.decode(false);
        
        SamlRequest samlRequestReader = new SamlRequest(samlRequest);
        samlRequestReader.readFromRequest();
        
        String issuerURL = samlRequestReader.getIssuerURL();
        String requestID = samlRequestReader.getRequestID();
        String acsURL = samlRequestReader.getAcsURL();
        
        SamlUser user = (SamlUser)(subject.getSession().getAttribute("user"));
        user.readKeyFromStr();
        
        String sessionId = (String)subject.getSession().getId();
        
        SamlResponse resp = new SamlResponse(user, issuerURL, requestID, acsURL, sessionId);
        resp.generateAuthnResponse();
        String respStr = resp.getSamlResponse();
        
        System.out.println(respStr);
        
        Map<String, Object> model = new HashMap<String, Object>();
        model.put("acsUrl", acsURL);
        model.put("samlResponse", resp.getBase64SamlResponse());
        model.put("relayState", relayState);
        
        return new ModelAndView("/page/sso/samlResponse.jsp", model);
    }
    
    
    /**
     * 用户登录
     * 
     * @return
     * @throws UnsupportedEncodingException 
     */
    @RequestMapping(value="/ssologout", method=RequestMethod.POST)
    public ModelAndView ssologout(String logoutRequest) {
        
        SamlDecoder decoder = new SamlDecoder(logoutRequest);
        logoutRequest = decoder.decode(true);
        
        SamlLogoutRequest logoutRequestReader = new SamlLogoutRequest(logoutRequest);
        logoutRequestReader.readFromLogoutRequest();
        
        Subject subject = SecurityUtils.getSubject();
        String principal = (String)subject.getPrincipal();
        
        if(principal.equals(logoutRequestReader.getNameId())) {
            subject.logout();
            
            //给请求SP返回LogoutResponse
            SamlLogoutResponse logoutResponse = new SamlLogoutResponse(logoutRequestReader.getIssuerURL(), logoutRequestReader.getNameId());
            String resp = logoutResponse.generateLogoutResponse();

            Map model = new HashMap();
            model.put("logoutResp", resp);
            
            return new ModelAndView("/page/sso/ssologout.jsp", model);
        }else{
            throw new IdeaSamlException("SamlLogoutRequest info not match.");
        }
    }
}
