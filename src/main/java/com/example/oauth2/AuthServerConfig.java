package com.example.oauth2;

import com.example.oauth2.enhancer.TargetAuthorityEnhancer;
import com.example.oauth2.granter.MfaTokenGranter;
import com.example.oauth2.granter.PasswordTokenGranter;
import com.example.oauth2.service.MfaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

    @Value("${oauth.client}")
    private String client;

    @Value("${oauth.secret}")
    private String secret;

    @Value("${oauth.key.alias}")
    private String keyAlias;

    @Value("${oauth.key.password}")
    private String keyPassword;

    @Value("${oauth.key.store}")
    private String keyStore;

    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Autowired
    private MfaService mfaService;

    @Autowired
    private TargetAuthorityEnhancer targetAuthorityEnhancer;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                .withClient(client)
                .secret(passwordEncoder().encode(secret))
                .scopes("read")
                .authorizedGrantTypes("password", "mfa")
                .accessTokenValiditySeconds(36000);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();

        tokenEnhancerChain.setTokenEnhancers(List.of(targetAuthorityEnhancer, accessTokenConverter()));

        endpoints
                .tokenEnhancer(tokenEnhancerChain)
                .tokenStore(tokenStore())
                .tokenGranter(tokenGranter(endpoints))
                .accessTokenConverter(accessTokenConverter());
    }

    private TokenGranter tokenGranter(final AuthorizationServerEndpointsConfigurer endpoints) {
        List<TokenGranter> granters = new ArrayList<>(List.of(endpoints.getTokenGranter()));
        granters.add(new PasswordTokenGranter(endpoints, authenticationManager, mfaService, targetAuthorityEnhancer));
        granters.add(new MfaTokenGranter(endpoints, mfaService));
        return new CompositeTokenGranter(granters);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security.checkTokenAccess("isAuthenticated()");
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource(keyStore), keyPassword.toCharArray());
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair(keyAlias));
        return converter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(4);
    }
}
