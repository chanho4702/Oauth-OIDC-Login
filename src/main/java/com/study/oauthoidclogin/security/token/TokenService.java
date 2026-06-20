package com.study.oauthoidclogin.security.token;

import com.study.oauthoidclogin.security.JwtException;
import com.study.oauthoidclogin.security.JwtProvider;
import com.study.oauthoidclogin.security.JwtSecurityProperties;
import com.study.oauthoidclogin.security.store.AccessTokenBlacklist;
import com.study.oauthoidclogin.security.store.RefreshTokenStore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.time.Instant;
import java.util.Collection;
import java.util.Map;

/**
 * ★ 토큰 발급/회전/무효화의 한 곳.
 *
 * 호스트 프로젝트의 로그인 컨트롤러는 이 서비스 한 곳만 호출하면 된다(내장 AuthController도 이걸 쓴다):
 *   - issueFor(...)  : 로그인 성공 후 AT(+RT) 발급
 *   - refresh(...)   : RT로 회전, 새 AT(+새 RT)
 *   - logout(...)    : RT 패밀리 무효화 + AT jti 블랙리스트
 *
 * refresh-token.enabled / blacklist.enabled 설정을 그대로 따른다.
 */
public class TokenService {

    private final JwtProvider jwtProvider;
    private final RefreshTokenStore refreshStore;
    private final AccessTokenBlacklist blacklist;
    private final UserDetailsService userDetailsService;
    private final JwtSecurityProperties props;

    public TokenService(JwtProvider jwtProvider, RefreshTokenStore refreshStore,
                        AccessTokenBlacklist blacklist, UserDetailsService userDetailsService,
                        JwtSecurityProperties props) {
        this.jwtProvider = jwtProvider;
        this.refreshStore = refreshStore;
        this.blacklist = blacklist;
        this.userDetailsService = userDetailsService;
        this.props = props;
    }

    /** 로그인 성공 → AT 발급(+RT 발급 if enabled). */
    public IssuedTokens issueFor(String username, Collection<? extends GrantedAuthority> authorities) {
        String role = extractRole(authorities);
        String accessToken = jwtProvider.issue(username, Map.of("role", role));

        String rtId = null;
        String fingerprint = "(RT 비활성)";
        if (props.getRefreshToken().isEnabled()) {
            RefreshTokenStore.Issued rt = refreshStore.issue(username);
            rtId = rt.tokenId();
            fingerprint = rt.fingerprint();
        }
        return new IssuedTokens(accessToken, rtId, fingerprint,
                props.getAccessToken().getValiditySeconds(),
                props.getRefreshToken().getValiditySeconds());
    }

    /** RT로 회전 → 새 AT(+새 RT). role 은 UserDetailsService 에서 다시 읽는다. */
    public IssuedTokens refresh(String presentedRefreshTokenId) {
        if (!props.getRefreshToken().isEnabled()) {
            throw new IllegalStateException("Refresh Token 기능이 비활성화되어 있습니다");
        }
        RefreshTokenStore.Issued rotated = refreshStore.rotate(presentedRefreshTokenId);
        UserDetails user = userDetailsService.loadUserByUsername(rotated.username());
        String role = extractRole(user.getAuthorities());
        String accessToken = jwtProvider.issue(rotated.username(), Map.of("role", role));

        return new IssuedTokens(accessToken, rotated.tokenId(), rotated.fingerprint(),
                props.getAccessToken().getValiditySeconds(),
                props.getRefreshToken().getValiditySeconds());
    }

    /** 로그아웃: RT 패밀리 무효화 + (가능하면) 현재 AT jti 블랙리스트. */
    public LogoutResult logout(String accessToken, String presentedRefreshTokenId) {
        boolean rtRevoked = false;
        if (props.getRefreshToken().isEnabled() && presentedRefreshTokenId != null) {
            refreshStore.revokeByToken(presentedRefreshTokenId);
            rtRevoked = true;
        }
        boolean atBlacklisted = false;
        if (props.getBlacklist().isEnabled() && accessToken != null) {
            try {
                Map<String, Object> claims = jwtProvider.verify(accessToken);
                long ttl = ((Number) claims.get("exp")).longValue() - Instant.now().getEpochSecond();
                blacklist.revoke((String) claims.get("jti"), ttl);
                atBlacklisted = ttl > 0;
            } catch (JwtException ignored) {
                // 이미 만료/위조면 블랙리스트 불필요
            }
        }
        return new LogoutResult(rtRevoked, atBlacklisted);
    }

    public record LogoutResult(boolean refreshTokenRevoked, boolean accessTokenBlacklisted) {}

    /** 권한("ROLE_USER") → role 클레임("USER"). */
    private String extractRole(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst()
                .map(a -> a.startsWith("ROLE_") ? a.substring("ROLE_".length()) : a)
                .orElse("USER");
    }
}
