package com.study.oauthoidclogin.security.endpoint;

import com.study.oauthoidclogin.security.store.RefreshTokenException;
import com.study.oauthoidclogin.security.web.RefreshCookieFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 컨트롤러 단계 예외 → JSON.
 *   - AuthenticationException : 로그인 실패(잘못된 자격) → 401
 *   - RefreshTokenException   : RT 회전 실패 → 401 + 쿠키 삭제
 * (필터 단계 인증 실패는 RestAuthenticationEntryPoint 가, 권한 부족은 RestAccessDeniedHandler 가 처리)
 */
@RestControllerAdvice
class SecurityExceptionHandler {

    private final RefreshCookieFactory cookieFactory;

    SecurityExceptionHandler(RefreshCookieFactory cookieFactory) {
        this.cookieFactory = cookieFactory;
    }

    @ExceptionHandler(AuthenticationException.class)
    ResponseEntity<Map<String, Object>> handleAuth(AuthenticationException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(error("BAD_CREDENTIALS", "아이디 또는 비밀번호가 올바르지 않습니다"));
    }

    @ExceptionHandler(RefreshTokenException.class)
    ResponseEntity<Map<String, Object>> handleRefresh(RefreshTokenException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.SET_COOKIE, cookieFactory.clear().toString())
                .body(error(e.getReason().name(), e.getMessage()));
    }

    private Map<String, Object> error(String code, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "UNAUTHORIZED");
        body.put("code", code);
        body.put("message", message);
        return body;
    }
}
