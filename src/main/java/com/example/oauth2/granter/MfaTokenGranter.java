package com.example.oauth2.granter;

import com.example.oauth2.service.MfaService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;

public class MfaTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "mfa";

    private final TokenStore tokenStore;

    private final MfaService mfaService;

    public MfaTokenGranter(AuthorizationServerEndpointsConfigurer endpointsConfigurer, MfaService mfaService) {
        super(endpointsConfigurer.getTokenServices(), endpointsConfigurer.getClientDetailsService(), endpointsConfigurer.getOAuth2RequestFactory(), GRANT_TYPE);

        this.tokenStore = endpointsConfigurer.getTokenStore();
        this.mfaService = mfaService;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        Map<String, String> parameters = new LinkedHashMap<>(tokenRequest.getRequestParameters());
        final String mfaToken = parameters.get("mfa_token");

        if (mfaToken != null) {
            OAuth2AccessToken accessToken = token(mfaToken);

            OAuth2Authentication authentication = this.tokenStore.readAuthentication(accessToken);

            if (authentication == null || !authentication.isAuthenticated()) {
                throw new InvalidTokenException("Invalid access token: " + mfaToken);
            }

            final String username = authentication.getName();
            if (parameters.containsKey("mfa_code")) {
                int code = parseCode(parameters.get("mfa_code"));
                if (mfaService.verifyCode(username, code)) {

                    return postAuthentication(client, tokenRequest, authentication, accessToken);
                }
            } else {
                throw new InvalidRequestException("Missing MFA code");
            }
            throw new InvalidGrantException("Invalid MFA code");
        } else {
            throw new InvalidRequestException("Missing MFA token");
        }
    }


    private OAuth2AccessToken token(String accessTokenValue) {
        OAuth2AccessToken accessToken = this.tokenStore.readAccessToken(accessTokenValue);

        if (accessToken == null) {
            throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
        } else if (accessToken.isExpired()) {
            this.tokenStore.removeAccessToken(accessToken);
            throw new InvalidTokenException("Access token expired: " + accessTokenValue);
        } else {
            return accessToken;
        }
    }

    @SuppressWarnings("all")
    private OAuth2Authentication postAuthentication(ClientDetails client, TokenRequest tokenRequest, OAuth2Authentication authentication, OAuth2AccessToken accessToken) {
        OAuth2Request storedOAuth2Request = this.getRequestFactory().createOAuth2Request(client, tokenRequest);

        List<SimpleGrantedAuthority> originalRoles = Stream.of(((String) accessToken.getAdditionalInformation().get("original_roles"))
                .split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(toList());

        UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken(
                authentication.getUserAuthentication().getPrincipal(),
                null,
                originalRoles
        );

        return new OAuth2Authentication(storedOAuth2Request, userAuthentication);
    }

    private int parseCode(String codeString) {
        try {
            return Integer.parseInt(codeString);
        } catch (NumberFormatException e) {
            throw new InvalidGrantException("Invalid MFA code");
        }
    }
}
