package com.study.oauthoidclogin.oauth;

import com.study.oauthoidclogin.security.token.IssuedTokens;
import com.study.oauthoidclogin.security.token.TokenService;
import com.study.oauthoidclogin.security.web.RefreshCookieFactory;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuth2LoginSuccessHandlerTest {

    @Test
    void issuesTokensSetsRtCookieAndRedirects() throws Exception {
        TokenService tokenService = mock(TokenService.class);
        when(tokenService.issueFor(eq("g@x.com"), anyCollection()))
                .thenReturn(new IssuedTokens("access-jwt", "rt-id-1", "fp", 900, 1209600));

        RefreshCookieFactory cookieFactory = mock(RefreshCookieFactory.class);
        when(cookieFactory.create("rt-id-1"))
                .thenReturn(ResponseCookie.from("REFRESH_TOKEN", "rt-id-1").path("/api/auth").build());

        OAuth2LoginSuccessHandler handler = new OAuth2LoginSuccessHandler(
                tokenService, cookieFactory, "http://localhost:5173/app");

        OidcIdToken idToken = new OidcIdToken("tok", Instant.now(), Instant.now().plusSeconds(60),
                Map.of("sub", "sub-1", "email", "g@x.com", "iss", "https://accounts.google.com"));
        OidcUser principal = new DefaultOidcUser(
                List.of(new SimpleGrantedAuthority("ROLE_USER")), idToken, "sub");
        Authentication auth = new UsernamePasswordAuthenticationToken(
                principal, null, principal.getAuthorities());

        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(req, res, auth);

        verify(tokenService).issueFor(eq("g@x.com"), anyCollection());
        assertThat(res.getHeader("Set-Cookie")).contains("REFRESH_TOKEN=rt-id-1");
        assertThat(res.getRedirectedUrl()).isEqualTo("http://localhost:5173/app");
    }
}
