package com.example.oauth2.enhancer;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class TargetAuthorityEnhancer implements TokenEnhancer {


    private final ThreadLocal<Collection<? extends GrantedAuthority>> authoritiesStore = new ThreadLocal<>();

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        if (authoritiesStore.get() != null) {
            Map<String, Object> additionalInfo = new HashMap<>();

            String authorities = authoritiesStore.get().stream().map(ga -> ga.toString()).collect(Collectors.joining(","));

            additionalInfo.put("original_roles", authorities);

            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);

            authoritiesStore.remove();
        }

        return accessToken;
    }

    public void targetAuthorities(Collection<? extends GrantedAuthority> authorities) {
        authoritiesStore.set(authorities);
    }
}