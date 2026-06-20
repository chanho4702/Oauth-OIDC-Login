package com.study.oauthoidclogin.security;

/**
 * JWT 검증 실패. code 로 원인을 구분해 화면/클라이언트가 "왜 실패했는지" 알 수 있게 한다.
 */
public class JwtException extends RuntimeException {

    public enum Code {
        MALFORMED,     // 형식이 JWT(a.b.c)가 아님
        BAD_SIGNATURE, // 서명 불일치 → 위조
        EXPIRED,       // 만료(exp 경과)
        REVOKED        // 서명·만료는 멀쩡하나 블랙리스트(jti)에 올라 무효화됨(로그아웃 등)
    }

    private final Code code;

    public JwtException(Code code, String message) {
        super(message);
        this.code = code;
    }

    public Code getCode() {
        return code;
    }
}
