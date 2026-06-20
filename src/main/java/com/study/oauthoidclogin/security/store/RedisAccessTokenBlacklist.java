package com.study.oauthoidclogin.security.store;

import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;

/** Redis 블랙리스트 — TTL=토큰 남은 수명. 만료되면 자동 정리되어 메모리 안 샌다. */
public class RedisAccessTokenBlacklist implements AccessTokenBlacklist {

    private final StringRedisTemplate redis;

    public RedisAccessTokenBlacklist(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public void revoke(String jti, long ttlSeconds) {
        if (jti == null || ttlSeconds <= 0) return;
        redis.opsForValue().set("blacklist:" + jti, "1", Duration.ofSeconds(ttlSeconds));
    }

    @Override
    public boolean isRevoked(String jti) {
        return jti != null && Boolean.TRUE.equals(redis.hasKey("blacklist:" + jti));
    }
}
