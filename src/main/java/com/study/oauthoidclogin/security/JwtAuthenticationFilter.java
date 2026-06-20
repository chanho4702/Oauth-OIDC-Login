package com.study.oauthoidclogin.security;

import com.study.oauthoidclogin.security.store.AccessTokenBlacklist;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * 매 요청에서 "Authorization: Bearer &lt;AT&gt;" 를 검증해 SecurityContext 를 채우는 필터.
 *
 *   - 토큰 없음        → 그냥 통과(보호 경로 차단은 인가 규칙에 맡김)
 *   - 검증 통과        → ROLE_* 권한을 담은 Authentication 을 SecurityContext 에 저장
 *   - 검증 실패        → 401 JSON 으로 즉시 응답(EntryPoint), 체인 끊음
 *   - 블랙리스트(jti)  → jwt-security.blacklist.enabled=true 일 때만 대조
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String ERROR_CODE_ATTR = "jwtErrorCode";
    public static final String ERROR_MESSAGE_ATTR = "jwtErrorMessage";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtProvider jwtProvider;
    private final AccessTokenBlacklist blacklist;
    private final AuthenticationEntryPoint entryPoint;
    private final boolean blacklistEnabled;

    public JwtAuthenticationFilter(JwtProvider jwtProvider, AccessTokenBlacklist blacklist,
                                   AuthenticationEntryPoint entryPoint, JwtSecurityProperties props) {
        this.jwtProvider = jwtProvider;
        this.blacklist = blacklist;
        this.entryPoint = entryPoint;
        this.blacklistEnabled = props.getBlacklist().isEnabled();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);   // 토큰 없음 → 통과
            return;
        }

        String token = header.substring(BEARER_PREFIX.length()).trim();
        try {
            Map<String, Object> claims = jwtProvider.verify(token);

            if (blacklistEnabled) {
                String jti = (String) claims.get("jti");
                if (blacklist.isRevoked(jti)) {
                    throw new JwtException(JwtException.Code.REVOKED,
                            "무효화된 토큰입니다 (로그아웃됨) — 다시 로그인하세요");
                }
            }

            String username = (String) claims.get("sub");
            String role = (String) claims.getOrDefault("role", "USER");
            var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));

            var authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
            authentication.setDetails(claims);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request, response);

        } catch (JwtException e) {
            SecurityContextHolder.clearContext();
            request.setAttribute(ERROR_CODE_ATTR, e.getCode().name());
            request.setAttribute(ERROR_MESSAGE_ATTR, e.getMessage());
            entryPoint.commence(request, response, new BadCredentialsException(e.getMessage(), e));
        }
    }
}
