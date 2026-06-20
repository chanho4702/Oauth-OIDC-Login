package com.study.oauthoidclogin.security.store;

/**
 * Refresh Token 저장소 — '서버가 기억하는' 상태(stateful). 회전/재사용 탐지/무효화의 무대.
 *
 * ★ pluggable 핵심: 이 인터페이스에 대고만 코딩하면, 구현이 인메모리든 Redis든 상관없다.
 *   - {@link InMemoryRefreshTokenStore} : 인프라 0, 단일 인스턴스/학습용
 *   - {@link RedisRefreshTokenStore}    : TTL=만료가 그대로 매핑되는 운영용
 *   어느 빈이 뜰지는 application.yml 의 jwt-security.store.type 이 정한다.
 *
 * 저장 모델(개념):
 *   refresh:&lt;tokenId&gt; = "&lt;familyId&gt;|&lt;username&gt;"  (TTL=RT 수명; 회전 후에도 남겨 재사용 탐지)
 *   family:&lt;familyId&gt;  = "&lt;현재 유효 tokenId&gt;"        (이 포인터가 가리키는 토큰만 유효)
 */
public interface RefreshTokenStore {

    record Issued(String tokenId, String familyId, String username) {
        public String fingerprint() {
            return RefreshTokenStore.fingerprint(tokenId);
        }
    }

    /** 로그인 시: 새 패밀리 + 첫 RT 발급. */
    Issued issue(String username);

    /** refresh 시: 검증 후 회전(설정에 따라). 실패 시 RefreshTokenException. */
    Issued rotate(String presentedTokenId);

    /** 로그아웃: 이 RT가 속한 패밀리 전체 무효화. */
    void revokeByToken(String tokenId);

    /** 화면 표시용 지문(토큰 본체 아님). */
    static String fingerprint(String tokenId) {
        if (tokenId == null || tokenId.length() < 8) return "(없음)";
        return tokenId.substring(0, 8) + "…(" + tokenId.length() + "자)";
    }
}
