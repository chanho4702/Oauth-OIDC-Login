package com.study.oauthoidclogin.oauth;

import com.study.oauthoidclogin.security.token.IssuedTokens;
import com.study.oauthoidclogin.security.token.TokenService;
import com.study.oauthoidclogin.security.web.RefreshCookieFactory;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;

/** OIDC 성공 → 우리 JWT 발급(RT 쿠키) → 프론트 콜백으로 리다이렉트. */
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2LoginSuccessHandler.class);

    private final TokenService tokenService;
    private final RefreshCookieFactory cookieFactory;
    private final String frontendRedirectUri;

    public OAuth2LoginSuccessHandler(TokenService tokenService, RefreshCookieFactory cookieFactory,
                                     String frontendRedirectUri) {
        this.tokenService = tokenService;
        this.cookieFactory = cookieFactory;
        this.frontendRedirectUri = frontendRedirectUri;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        OidcUser user = (OidcUser) authentication.getPrincipal();

        // (실습) OIDC 산출물 = Google ID Token 클레임 관찰
        log.info("[OIDC] ID Token claims: iss={}, sub={}, aud={}, email={}",
                user.getIdToken().getIssuer(), user.getSubject(),
                user.getIdToken().getAudience(), user.getEmail());

        IssuedTokens tokens = tokenService.issueFor(user.getEmail(), authentication.getAuthorities());
        if (tokens.refreshTokenId() != null) {
            response.addHeader(HttpHeaders.SET_COOKIE, cookieFactory.create(tokens.refreshTokenId()).toString());
        }
        getRedirectStrategy().sendRedirect(request, response, frontendRedirectUri);
    }
}
