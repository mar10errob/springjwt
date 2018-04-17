package com.nouhoun.springboot.jwt.integration.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

@Component
public class UserProviderAuthentication implements AuthenticationProvider {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        logger.info("Se ha generado el usuario en custom provider");

        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        if (name.equals("jhon.doe")) {

            // use the credentials
            // and authenticate against the third-party system
            return new OAuth2Authentication(null, authentication);
        } else {
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(OAuth2Authentication.class);
    }
}
