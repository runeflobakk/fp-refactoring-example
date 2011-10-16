package com.github.runeflobakk.security;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class MyPrincipal extends User {

    private final String securityLevel;

    public MyPrincipal(String username, String password, String securityLevel, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, true, true, true, true, authorities);
        this.securityLevel = securityLevel;
    }

    public String getSecurityLevel() {
        return securityLevel;
    }

}
