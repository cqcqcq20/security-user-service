package com.example.music.user.config.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class SmsCodeAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private String code;//验证码
    private String area;//国际区号
    private String type;//国际区号

    public SmsCodeAuthenticationToken(Object principal, String code,String area,String type) {
        super(null);
        this.principal = principal;
        this.code = code;
        this.area = area;
        this.type = type;
        this.setAuthenticated(false);
    }

    public SmsCodeAuthenticationToken(Object principal,String area,String type, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.area = area;
        this.type = type;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public String getArea() {
        return area;
    }

    public String getCode() {
        return code;
    }

    public String getType() {
        return type;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        } else {
            super.setAuthenticated(false);
        }
    }
}
