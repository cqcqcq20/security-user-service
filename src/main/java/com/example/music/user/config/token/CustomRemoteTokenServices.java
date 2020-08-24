package com.example.music.user.config.token;

import com.example.music.auth.basic.config.token.CustomUserAuthenticationConverter;
import com.example.music.user.service.LocalAccessTokenService;
import com.example.music.user.service.RedisTokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;

@Slf4j
public class CustomRemoteTokenServices extends RemoteTokenServices {

    private String accessTokenUri;

    private RestOperations restTemplate;

    private String checkTokenEndpointUrl;

    private String clientId;

    private String clientSecret;

    private String refresh_token = "refresh_token";

    private String tokenName = "token";

    private DefaultAccessTokenConverter tokenConverter = new DefaultAccessTokenConverter();

    private LocalAccessTokenService localAccessTokenService;

    public CustomRemoteTokenServices(LocalAccessTokenService localAccessTokenService) {
        restTemplate = new RestTemplate();
        tokenConverter.setUserTokenConverter(new CustomUserAuthenticationConverter());
        this.localAccessTokenService = localAccessTokenService;
        ((RestTemplate) restTemplate).setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            // Ignore 400
            public void handleError(ClientHttpResponse response) throws IOException {
                if (response.getRawStatusCode() != 400) {
                    super.handleError(response);
                }
            }
        });
    }

    public void setAccessTokenUri(String accessTokenUri) {
        this.accessTokenUri = accessTokenUri;
    }

    public void refreshToken(String refreshToken) {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(refresh_token, refreshToken);
        formData.add("grant_type", "refresh_token");
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", getAuthorizationHeader(clientId, clientSecret));
        Map<String, Object> map = postForMap(accessTokenUri, formData, headers);
    }

    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void setCheckTokenEndpointUrl(String checkTokenEndpointUrl) {
        this.checkTokenEndpointUrl = checkTokenEndpointUrl;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void setAccessTokenConverter(DefaultAccessTokenConverter accessTokenConverter) {
        this.tokenConverter = accessTokenConverter;
    }

    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        Map<String, Object> map = localAccessTokenService != null ? localAccessTokenService.getAccessToken(accessToken) : null;
        if (map == null) {
            formData.add(tokenName, accessToken);
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", getAuthorizationHeader(clientId, clientSecret));
            map = postForMap(checkTokenEndpointUrl, formData, headers);

            if (map.containsKey("error")) {
                if (logger.isDebugEnabled()) {
                    logger.debug("check_token returned error: " + map.get("error"));
                }
                throw new InvalidTokenException(accessToken);
            }

            // gh-838
            if (!Boolean.TRUE.equals(map.get("active"))) {
                logger.debug("check_token returned active attribute: " + map.get("active"));
                throw new InvalidTokenException(accessToken);
            }
            if (localAccessTokenService != null) localAccessTokenService.storeAccessToken(accessToken,map,Long.parseLong(map.get("exp").toString()));
        }

        return tokenConverter.extractAuthentication(map);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        throw new UnsupportedOperationException("Not supported: read access token");
    }

    private String getAuthorizationHeader(String clientId, String clientSecret) {

        if(clientId == null || clientSecret == null) {
            logger.warn("Null Client ID or Client Secret detected. Endpoint that requires authentication will reject request with 401 error.");
        }

        String creds = String.format("%s:%s", clientId, clientSecret);
        try {
            return "Basic " + new String(Base64.encode(creds.getBytes("UTF-8")));
        }
        catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Could not convert String");
        }
    }

    private Map<String, Object> postForMap(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        @SuppressWarnings("rawtypes")
        Map map = restTemplate.exchange(path, HttpMethod.POST,
                new HttpEntity<MultiValueMap<String, String>>(formData, headers), Map.class).getBody();
        @SuppressWarnings("unchecked")
        Map<String, Object> result = map;
        return result;
    }
}
