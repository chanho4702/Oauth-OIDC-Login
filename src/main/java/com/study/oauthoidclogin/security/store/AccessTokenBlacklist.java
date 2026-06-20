package com.study.oauthoidclogin.security.store;

/**
 * Access Token jti 블랙리스트 — 로그아웃/탈취 시 만료 전 AT도 즉시 무효화.
 * 구현은 인메모리/Redis 두 가지(store.type 으로 선택).
 */
public interface AccessTokenBlacklist {

    /** jti 무효 등록. ttlSeconds = 토큰의 남은 수명(그 뒤엔 어차피 만료). */
    void revoke(String jti, long ttlSeconds);

    /** jti 가 무효화됐는지? */
    boolean isRevoked(String jti);
}
