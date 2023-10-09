package com.example.ResourceServer.configuration;

import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.util.WebUtils;

import java.net.URL;
import java.util.Collection;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

@EnableWebSecurity // Enable Spring Security’s web security support
// @EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // To configure method-level security
@Configuration
public class AccessConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwks-uri}")
    private String keyUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String iss;

    private Collection<OAuth2TokenValidator<Jwt>> validators;

    @Autowired
    private ApplicationContext applicationContext;

    /* Filter requests for authentication and authorization */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.addFilterBefore(new RefreshAccessTokenFilter(), SecurityContextPersistenceFilter.class);
        return http
                .csrf((csrf) -> csrf.disable())
                .authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers(HttpMethod.GET, "/api/redirect/mobile", "/error", "/reset").permitAll()
                                .requestMatchers(HttpMethod.POST, "/api/token", "/api/token/refresh", "/generateCodeVerifierAndCodeChallenge").permitAll()
                                .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder()))
                        .bearerTokenResolver(this::resolver)).build();
    }

    public String resolver(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, "AuthCookie");
        if(cookie != null) {
            return cookie.getValue();
        }
        return null;
    }

    /* Validator checking for client ID in token */
    public OAuth2TokenValidator<Jwt> clientValidator() {
        return new JwtClaimValidator<>(
                OAuth2TokenIntrospectionClaimNames.CLIENT_ID,
                clientID -> clientID.equals("19kungvqs1dmi2q335nfjgta7l")
        );
    }

    /* Combining token expire, ISS and client ID validator */
    public OAuth2TokenValidator<Jwt> tokenValidator() {
        this.validators =
                List.of(new JwtTimestampValidator(),
                        new JwtIssuerValidator(iss),
                        clientValidator());
        return new DelegatingOAuth2TokenValidator<>(this.validators);
    }

    /* Passing combined validator outcome and JWKS URI to token decoder */

    @Bean
    public JwtDecoder jwtDecoder() {

        System.out.println("I am decoder");

        JWSKeySelector<SecurityContext> jwsKeySelector = null;
        DefaultJWTProcessor<SecurityContext> jwtProcessor = null;

        try {
            URL jwksUrl = new URL(keyUri);

            DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(
                    5000,
                    5000);

            /* Schedule public key refresh in (TTL - (refresh timeout + refresh ahead timeout)) */
            JWKSource<SecurityContext> jwkSource = JWKSourceBuilder.create(jwksUrl, resourceRetriever).cache(360000, 60000).rateLimited(30000).refreshAheadCache(60000/*30000*/, true).build();
            jwsKeySelector = JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(jwkSource);

            jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(jwsKeySelector);

        }
        catch (Exception e) {
            System.out.println("error---->"+e);
            e.printStackTrace();
        }

        System.out.println("success---->"+jwtProcessor);
        return new NimbusJwtDecoder(jwtProcessor);
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
                    String[] groups;
                    if (jwt.getClaims().containsKey("cognito:groups")) {
                        groups= jwt.getClaims().get("cognito:groups").toString().replaceAll("\\[|\\]", "").split("\\s");
                    }
                    else {
                        groups = new String[0];
                    }
                    return Arrays.stream(groups)
                            .map(groupName -> new SimpleGrantedAuthority("ROLE_" + groupName.toUpperCase(Locale.ROOT)))
                            .collect(Collectors.toSet());
                }
        );

        return jwtAuthenticationConverter;
    }
}
