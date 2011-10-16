package com.github.runeflobakk.security;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class MyPrincipal extends User {

    public MyPrincipal(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, true, true, true, true, authorities);
    }

    public String getSecurityLevel() {
        throw new UnsupportedOperationException();
    }

}
