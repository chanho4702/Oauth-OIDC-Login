package com.study.oauthoidclogin.security.store;

/** Refresh Token 처리 실패. reason 으로 원인 구분. */
public class RefreshTokenException extends RuntimeException {

    public enum Reason {
        INVALID,        // 없음/만료 — 저장소에 흔적 없음
        REUSE_DETECTED, // 폐기된 옛 RT 재사용 → 탈취 의심 → 패밀리 무효화
        REVOKED         // 패밀리가 이미 무효화됨(로그아웃/폭파)
    }

    private final Reason reason;

    public RefreshTokenException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
