package com.study.oauthoidclogin.security.web;

import com.study.oauthoidclogin.security.JwtSecurityProperties;
import org.springframework.http.ResponseCookie;

import java.time.Duration;

/** RT를 담는 HttpOnly 쿠키를 만들고/지운다. 모든 속성은 jwt-security.refresh-token.cookie.* 에서. */
public class RefreshCookieFactory {

    private final JwtSecurityProperties.RefreshToken.Cookie cfg;
    private final Duration maxAge;

    public RefreshCookieFactory(JwtSecurityProperties props) {
        this.cfg = props.getRefreshToken().getCookie();
        this.maxAge = Duration.ofSeconds(props.getRefreshToken().getValiditySeconds());
    }

    public ResponseCookie create(String refreshToken) {
        return base(refreshToken, maxAge).build();
    }

    public ResponseCookie clear() {
        return base("", Duration.ZERO).build();
    }

    public String cookieName() {
        return cfg.getName();
    }

    private ResponseCookie.ResponseCookieBuilder base(String value, Duration age) {
        return ResponseCookie.from(cfg.getName(), value)
                .httpOnly(cfg.isHttpOnly())
                .secure(cfg.isSecure())
                .sameSite(cfg.getSameSite())
                .path(cfg.getPath())
                .maxAge(age);
    }
}
