package com.study.oauthoidclogin.security.endpoint;

import com.study.oauthoidclogin.security.token.IssuedTokens;
import com.study.oauthoidclogin.security.token.TokenService;
import com.study.oauthoidclogin.security.user.UserAccountService;
import com.study.oauthoidclogin.security.web.RefreshCookieFactory;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.Valid;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 내장 인증 API. jwt-security.auth-endpoints.enabled=true(기본) 일 때만 노출된다.
 * 호스트가 자기 로그인 컨트롤러를 쓰고 싶으면 false 로 끄고 TokenService 를 직접 호출하면 된다.
 *
 *   POST /api/auth/login   : AuthenticationManager 인증 → AT(본문) + RT(쿠키)
 *   POST /api/auth/refresh : 쿠키 RT 회전 → 새 AT + 새 RT
 *   POST /api/auth/logout  : RT 무효화 + AT 블랙리스트 + 쿠키 삭제
 *   POST /api/auth/signup  : UserAccountService 가 있을 때만(기본 인메모리) 가입
 */
@RestController
@RequestMapping("/api/auth")
@ConditionalOnProperty(name = "jwt-security.auth-endpoints.enabled", havingValue = "true", matchIfMissing = true)
class AuthController {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final RefreshCookieFactory cookieFactory;
    private final ObjectProvider<UserAccountService> userAccountService;

    AuthController(AuthenticationManager authenticationManager, TokenService tokenService,
                   RefreshCookieFactory cookieFactory, ObjectProvider<UserAccountService> userAccountService) {
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
        this.cookieFactory = cookieFactory;
        this.userAccountService = userAccountService;
    }

    @PostMapping("/login")
    ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest request) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));
        IssuedTokens tokens = tokenService.issueFor(auth.getName(), auth.getAuthorities());
        return tokenResponse(tokens);
    }

    @PostMapping("/refresh")
    ResponseEntity<Map<String, Object>> refresh(HttpServletRequest httpRequest) {
        String presented = readRefreshCookie(httpRequest);
        if (presented == null) {
            throw new com.study.oauthoidclogin.security.store.RefreshTokenException(
                    com.study.oauthoidclogin.security.store.RefreshTokenException.Reason.INVALID,
                    "Refresh Token 쿠키가 없습니다 — 먼저 로그인하세요");
        }
        return tokenResponse(tokenService.refresh(presented));
    }

    @PostMapping("/logout")
    ResponseEntity<Map<String, Object>> logout(
            HttpServletRequest httpRequest,
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        String accessToken = (authorization != null && authorization.startsWith("Bearer "))
                ? authorization.substring("Bearer ".length()).trim() : null;
        TokenService.LogoutResult result = tokenService.logout(accessToken, readRefreshCookie(httpRequest));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "로그아웃 완료");
        body.put("refreshTokenRevoked", result.refreshTokenRevoked());
        body.put("accessTokenBlacklisted", result.accessTokenBlacklisted());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookieFactory.clear().toString())
                .body(body);
    }

    @PostMapping("/signup")
    ResponseEntity<Map<String, String>> signup(@Valid @RequestBody SignupRequest request) {
        UserAccountService accounts = userAccountService.getIfAvailable();
        if (accounts == null) {
            throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED,
                    "이 UserDetailsService 는 가입을 지원하지 않습니다 (UserAccountService 미구현)");
        }
        try {
            accounts.register(request.username(), request.password(), "USER");
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of("username", request.username(), "message", "회원가입 완료"));
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
        }
    }

    // ── helpers ──────────────────────────────────────────────
    private ResponseEntity<Map<String, Object>> tokenResponse(IssuedTokens t) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("tokenType", "Bearer");
        body.put("accessToken", t.accessToken());
        body.put("expiresIn", t.accessTokenExpiresIn());
        body.put("refreshExpiresIn", t.refreshTokenExpiresIn());
        body.put("refreshTokenFingerprint", t.refreshTokenFingerprint());

        ResponseEntity.BodyBuilder builder = ResponseEntity.ok();
        if (t.refreshTokenId() != null) {
            ResponseCookie cookie = cookieFactory.create(t.refreshTokenId());
            builder.header(HttpHeaders.SET_COOKIE, cookie.toString());
        }
        return builder.body(body);
    }

    private String readRefreshCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie c : request.getCookies()) {
            if (c.getName().equals(cookieFactory.cookieName())) return c.getValue();
        }
        return null;
    }

    record LoginRequest(@NotBlank String username, @NotBlank String password) {}

    record SignupRequest(@NotBlank String username,
                         @NotBlank @Size(min = 4, message = "비밀번호는 4자 이상") String password) {}
}
