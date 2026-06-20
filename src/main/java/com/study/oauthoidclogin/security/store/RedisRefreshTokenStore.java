package com.study.oauthoidclogin.security.store;

import com.study.oauthoidclogin.security.JwtSecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

/**
 * Redis 구현 — 운영용. 'TTL=토큰 만료, 키 삭제=무효화'가 1:1로 매핑된다.
 * 인메모리 구현과 동일한 회전/재사용 탐지 정책을 따르되, 저장만 Redis로 바뀐다.
 */
public class RedisRefreshTokenStore implements RefreshTokenStore {

    private static final Logger log = LoggerFactory.getLogger(RedisRefreshTokenStore.class);
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final SecureRandom random = new SecureRandom();
    private final StringRedisTemplate redis;
    private final Duration ttl;
    private final boolean rotation;
    private final boolean reuseDetection;

    public RedisRefreshTokenStore(StringRedisTemplate redis, JwtSecurityProperties props) {
        this.redis = redis;
        this.ttl = Duration.ofSeconds(props.getRefreshToken().getValiditySeconds());
        this.rotation = props.getRefreshToken().isRotation();
        this.reuseDetection = props.getRefreshToken().isReuseDetection();
    }

    @Override
    public Issued issue(String username) {
        String familyId = randomId();
        String tokenId = randomId();
        redis.opsForValue().set(tokenKey(tokenId), familyId + "|" + username, ttl);
        redis.opsForValue().set(familyKey(familyId), tokenId, ttl);
        return new Issued(tokenId, familyId, username);
    }

    @Override
    public Issued rotate(String presentedTokenId) {
        String stored = redis.opsForValue().get(tokenKey(presentedTokenId));
        if (stored == null) {
            throw new RefreshTokenException(RefreshTokenException.Reason.INVALID,
                    "Refresh Token이 없거나 만료되었습니다 — 다시 로그인하세요");
        }
        String[] meta = stored.split("\\|", 2);
        String familyId = meta[0];
        String username = meta[1];

        String currentTokenId = redis.opsForValue().get(familyKey(familyId));
        if (currentTokenId == null) {
            throw new RefreshTokenException(RefreshTokenException.Reason.REVOKED,
                    "이미 무효화된 세션의 토큰입니다 — 다시 로그인하세요");
        }
        if (!currentTokenId.equals(presentedTokenId)) {
            if (reuseDetection) {
                redis.delete(familyKey(familyId));
                log.warn("RT 재사용 탐지! family={} 폭파", familyId);
                throw new RefreshTokenException(RefreshTokenException.Reason.REUSE_DETECTED,
                        "재사용된(폐기된) Refresh Token 감지 — 세션 전체를 무효화했습니다");
            }
            throw new RefreshTokenException(RefreshTokenException.Reason.INVALID,
                    "이미 회전된 옛 Refresh Token 입니다");
        }

        if (!rotation) {
            return new Issued(presentedTokenId, familyId, username);
        }
        String newTokenId = randomId();
        redis.opsForValue().set(tokenKey(newTokenId), familyId + "|" + username, ttl);
        redis.opsForValue().set(familyKey(familyId), newTokenId, ttl);
        return new Issued(newTokenId, familyId, username);
    }

    @Override
    public void revokeByToken(String tokenId) {
        String stored = redis.opsForValue().get(tokenKey(tokenId));
        if (stored == null) return;
        redis.delete(familyKey(stored.split("\\|", 2)[0]));
    }

    private String tokenKey(String id)   { return "refresh:" + id; }
    private String familyKey(String id)  { return "family:" + id; }

    private String randomId() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return URL_ENCODER.encodeToString(bytes);
    }
}
