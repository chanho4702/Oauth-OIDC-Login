package com.study.oauthoidclogin.security.store;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/** 인메모리 블랙리스트 — jti → 만료시각(epoch sec). 읽을 때 lazy 만료. */
public class InMemoryAccessTokenBlacklist implements AccessTokenBlacklist {

    private final ConcurrentHashMap<String, Long> revoked = new ConcurrentHashMap<>();

    @Override
    public void revoke(String jti, long ttlSeconds) {
        if (jti == null || ttlSeconds <= 0) return;
        revoked.put(jti, Instant.now().getEpochSecond() + ttlSeconds);
    }

    @Override
    public boolean isRevoked(String jti) {
        if (jti == null) return false;
        Long expireAt = revoked.get(jti);
        if (expireAt == null) return false;
        if (Instant.now().getEpochSecond() >= expireAt) {
            revoked.remove(jti);
            return false;
        }
        return true;
    }
}
