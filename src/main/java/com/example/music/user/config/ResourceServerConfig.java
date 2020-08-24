package com.example.music.user.config;

import com.example.music.auth.basic.config.UnAuthenticationEntryPoint;
import com.example.music.auth.basic.config.handler.AuthAccessDeniedHandler;
import com.example.music.user.config.token.CustomRemoteTokenServices;
import com.example.music.user.service.LocalAccessTokenService;
import com.example.music.user.service.RedisTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.web.client.RestTemplate;

/**
 * SecurityConfig
 *
 * @author fengzheng
 * @date 2019/10/11
 */
@Configuration
@EnableResourceServer
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Value("${security.oauth2.client.client-id}")
    private String clientId;

    @Value("${security.oauth2.client.client-secret}")
    private String secret;

    @Value("${security.oauth2.authorization.check-token-access}")
    private String checkTokenEndpointUrl;

    @Value("${security.oauth2.client.access-token-uri}")
    private String accessTokenUri;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private RedisConnectionFactory connectionFactory;

    @Autowired
    private LocalAccessTokenService localAccessTokenService;

    @Bean
    public TokenStore redisTokenStore() {
        return new RedisTokenStore(connectionFactory);
    }

    @Bean
    public CustomRemoteTokenServices tokenService() {
//        CustomRemoteTokenServices tokenService = new CustomRemoteTokenServices(localAccessTokenService);
        CustomRemoteTokenServices tokenService = new CustomRemoteTokenServices(null);
        tokenService.setClientId(clientId);
        tokenService.setClientSecret(secret);
        tokenService.setCheckTokenEndpointUrl(checkTokenEndpointUrl);
        tokenService.setRestTemplate(restTemplate);
        tokenService.setAccessTokenUri(accessTokenUri);
        return tokenService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.tokenServices(tokenService()).authenticationEntryPoint(new AuthExceptionEntryPoint());
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/login/**", "/sms/**", "/password/forget","/actuator/**").permitAll()
                .and().authorizeRequests().anyRequest().authenticated()
                .and().exceptionHandling().accessDeniedHandler(new AuthAccessDeniedHandler()).authenticationEntryPoint(provideUnAuthenticationEntryPoint())
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().csrf().disable()
                .headers().cacheControl().disable();
    }

    private UnAuthenticationEntryPoint provideUnAuthenticationEntryPoint() {
        return new UnAuthenticationEntryPoint();
    }

}
