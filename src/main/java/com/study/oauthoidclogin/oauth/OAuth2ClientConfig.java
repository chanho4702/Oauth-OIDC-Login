package com.study.oauthoidclogin.oauth;

import com.study.oauthoidclogin.security.token.TokenService;
import com.study.oauthoidclogin.security.web.RefreshCookieFactory;
import com.study.oauthoidclogin.user.DbUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;

@Configuration
public class OAuth2ClientConfig {

    /** 인가요청에 PKCE(code_challenge/S256) 추가. */
    @Bean
    public OAuth2AuthorizationRequestResolver pkceResolver(ClientRegistrationRepository repo) {
        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(repo, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }

    @Bean
    public CookieAuthorizationRequestRepository cookieAuthorizationRequestRepository() {
        return new CookieAuthorizationRequestRepository();
    }

    @Bean
    public CustomOidcUserService customOidcUserService(DbUserDetailsService provisioning) {
        return new CustomOidcUserService(new OidcUserService(), provisioning);
    }

    @Bean
    public OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler(
            TokenService tokenService, RefreshCookieFactory cookieFactory,
            @Value("${app.oauth.frontend-redirect-uri}") String frontendRedirectUri) {
        return new OAuth2LoginSuccessHandler(tokenService, cookieFactory, frontendRedirectUri);
    }
}
