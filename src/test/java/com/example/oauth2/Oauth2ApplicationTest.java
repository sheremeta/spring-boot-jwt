package com.example.oauth2;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import static org.apache.commons.codec.binary.Base64.encodeBase64;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpMethod.POST;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class Oauth2ApplicationTest {

    private final Logger LOG = LoggerFactory.getLogger(Oauth2ApplicationTest.class);

    @LocalServerPort
    private int port;

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
    private TestRestTemplate restTemplate;

    @Test
    @SuppressWarnings("all")
    public void encryptDecrypt() throws Exception {
        String url = String.format("http://localhost:%d/oauth/token?grant_type=client_credentials", port);

        OAuth2AccessToken token = this.restTemplate.exchange(url, POST, headers(), OAuth2AccessToken.class).getBody();

        assertJWT(token);
    }

    private void assertJWT(OAuth2AccessToken jwt) throws Exception {
        Jws<Claims> jws = Jwts.parser()
                .setSigningKey(publicKey().getPublic())
                .parseClaimsJws(jwt.getValue());

        LOG.info(jws.toString());
    }

    private HttpEntity<String> headers() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(AUTHORIZATION, "Basic " + new String(encodeBase64(String.format("%s:%s", client, secret).getBytes())));
        return new HttpEntity<>(headers);
    }

    private KeyPair publicKey() throws Exception {
        Resource resource = new ClassPathResource(keyStore);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(resource.getInputStream(), keyPassword.toCharArray());

        String alias = keyAlias;

        Key key = keystore.getKey(alias, keyPassword.toCharArray());

        Certificate cert = keystore.getCertificate(alias);

        PublicKey publicKey = cert.getPublicKey();

        return new KeyPair(publicKey, (PrivateKey) key);
    }
}
