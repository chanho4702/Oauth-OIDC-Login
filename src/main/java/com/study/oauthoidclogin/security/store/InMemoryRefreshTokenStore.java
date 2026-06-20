package com.study.oauthoidclogin.security.store;

import com.study.oauthoidclogin.security.JwtSecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 인메모리 구현 — 인프라 0. 앱 재시작하면 사라진다(단일 인스턴스/학습용).
 * 만료는 값에 expireAt(epoch sec)을 함께 저장해 읽을 때 lazy 체크한다(Redis TTL 흉내).
 *
 * rotation/reuse-detection 정책은 jwt-security.refresh-token.* 설정을 따른다.
 */
public class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private static final Logger log = LoggerFactory.getLogger(InMemoryRefreshTokenStore.class);
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private record Entry(String value, long expireAt) {
        boolean expired() { return Instant.now().getEpochSecond() >= expireAt; }
    }

    private final SecureRandom random = new SecureRandom();
    private final ConcurrentHashMap<String, Entry> tokens = new ConcurrentHashMap<>();  // tokenId -> "family|user"
    private final ConcurrentHashMap<String, Entry> families = new ConcurrentHashMap<>(); // familyId -> tokenId

    private final long ttlSeconds;
    private final boolean rotation;
    private final boolean reuseDetection;

    public InMemoryRefreshTokenStore(JwtSecurityProperties props) {
        this.ttlSeconds = props.getRefreshToken().getValiditySeconds();
        this.rotation = props.getRefreshToken().isRotation();
        this.reuseDetection = props.getRefreshToken().isReuseDetection();
    }

    @Override
    public Issued issue(String username) {
        String familyId = randomId();
        String tokenId = randomId();
        put(tokens, "refresh:" + tokenId, familyId + "|" + username);
        put(families, "family:" + familyId, tokenId);
        return new Issued(tokenId, familyId, username);
    }

    @Override
    public Issued rotate(String presentedTokenId) {
        String stored = get(tokens, "refresh:" + presentedTokenId);
        if (stored == null) {
            throw new RefreshTokenException(RefreshTokenException.Reason.INVALID,
                    "Refresh Token이 없거나 만료되었습니다 — 다시 로그인하세요");
        }
        String[] meta = stored.split("\\|", 2);
        String familyId = meta[0];
        String username = meta[1];

        String currentTokenId = get(families, "family:" + familyId);
        if (currentTokenId == null) {
            throw new RefreshTokenException(RefreshTokenException.Reason.REVOKED,
                    "이미 무효화된 세션의 토큰입니다 — 다시 로그인하세요");
        }
        if (!currentTokenId.equals(presentedTokenId)) {
            if (reuseDetection) {
                families.remove("family:" + familyId);
                log.warn("RT 재사용 탐지! family={} 폭파", familyId);
                throw new RefreshTokenException(RefreshTokenException.Reason.REUSE_DETECTED,
                        "재사용된(폐기된) Refresh Token 감지 — 세션 전체를 무효화했습니다");
            }
            throw new RefreshTokenException(RefreshTokenException.Reason.INVALID,
                    "이미 회전된 옛 Refresh Token 입니다");
        }

        if (!rotation) {
            return new Issued(presentedTokenId, familyId, username); // 회전 끔 → 같은 RT 유지
        }
        String newTokenId = randomId();
        put(tokens, "refresh:" + newTokenId, familyId + "|" + username);
        put(families, "family:" + familyId, newTokenId);
        return new Issued(newTokenId, familyId, username);
    }

    @Override
    public void revokeByToken(String tokenId) {
        String stored = get(tokens, "refresh:" + tokenId);
        if (stored == null) return;
        String familyId = stored.split("\\|", 2)[0];
        families.remove("family:" + familyId);
    }

    private void put(ConcurrentHashMap<String, Entry> map, String key, String value) {
        map.put(key, new Entry(value, Instant.now().getEpochSecond() + ttlSeconds));
    }

    private String get(ConcurrentHashMap<String, Entry> map, String key) {
        Entry e = map.get(key);
        if (e == null) return null;
        if (e.expired()) { map.remove(key); return null; }
        return e.value();
    }

    private String randomId() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return URL_ENCODER.encodeToString(bytes);
    }
}
