package com.study.oauthoidclogin.oauth;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.Arrays;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class CookieAuthorizationRequestRepositoryTest {

    AuthorizationRequestRepository<OAuth2AuthorizationRequest> repo =
            new CookieAuthorizationRequestRepository();

    private OAuth2AuthorizationRequest sample() {
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .clientId("client-1")
                .redirectUri("http://localhost:8080/login/oauth2/code/google")
                .scope("openid")
                .state("state-xyz")
                .build();
    }

    @Test
    void saveThenLoadRoundTrips() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();

        repo.saveAuthorizationRequest(sample(), req, res);

        // 응답 쿠키를 다음 요청으로 옮긴다
        Cookie cookie = res.getCookie("OAUTH2_AUTH_REQUEST");
        assertThat(cookie).isNotNull();
        req.setCookies(cookie);

        OAuth2AuthorizationRequest loaded = repo.loadAuthorizationRequest(req);
        assertThat(loaded).isNotNull();
        assertThat(loaded.getState()).isEqualTo("state-xyz");
        assertThat(loaded.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
    }

    @Test
    void removeDeletesCookie() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        repo.saveAuthorizationRequest(sample(), req, res);
        req.setCookies(res.getCookie("OAUTH2_AUTH_REQUEST"));

        OAuth2AuthorizationRequest removed = repo.removeAuthorizationRequest(req, res);
        assertThat(removed).isNotNull();
        assertThat(removed.getState()).isEqualTo("state-xyz");
        // Spring 7 MockHttpServletResponse.getCookie() returns the first match; use getCookies()
        // stream to find the last-added cookie (the deletion cookie with maxAge=0).
        Optional<Cookie> cleared = Arrays.stream(res.getCookies())
                .filter(c -> "OAUTH2_AUTH_REQUEST".equals(c.getName()))
                .reduce((a, b) -> b);
        assertThat(cleared).isPresent();
        assertThat(cleared.get().getMaxAge()).isZero();
    }
}
