package com.study.oauthoidclogin.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.study.oauthoidclogin.security.store.*;
import com.study.oauthoidclogin.security.token.TokenService;
import com.study.oauthoidclogin.security.user.InMemoryUserAccountService;
import com.study.oauthoidclogin.security.web.RefreshCookieFactory;
import com.study.oauthoidclogin.security.web.RestAccessDeniedHandler;
import com.study.oauthoidclogin.security.web.RestAuthenticationEntryPoint;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * ★ 모듈의 중심 조립부. application.yml(JwtSecurityProperties)을 읽어
 *   필터 체인·인가 규칙·빈(저장소/핸들러/토큰서비스)을 전부 구성한다.
 *
 * 저장소는 jwt-security.store.type 으로 인메모리(기본)/Redis 가 갈린다 → @ConditionalOnProperty.
 * 사용자 서비스는 호스트가 자기 UserDetailsService 를 정의하면 그게 이긴다 → @ConditionalOnMissingBean.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity                                   // @PreAuthorize 활성화
@EnableConfigurationProperties(JwtSecurityProperties.class)
public class JwtSecurityConfig {

    // ── 공통 빈 ────────────────────────────────────────────────
    /** JSON 응답/JWT 직렬화용. 호스트에 이미 ObjectMapper 빈이 있으면 그걸 쓴다(모듈은 자급자족). */
    @Bean
    @ConditionalOnMissingBean(ObjectMapper.class)
    public ObjectMapper jwtSecurityObjectMapper() {
        return new ObjectMapper();
    }

    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public RestAuthenticationEntryPoint jwtAuthenticationEntryPoint(ObjectMapper objectMapper) {
        return new RestAuthenticationEntryPoint(objectMapper);
    }

    @Bean
    public RestAccessDeniedHandler jwtAccessDeniedHandler(ObjectMapper objectMapper) {
        return new RestAccessDeniedHandler(objectMapper);
    }

    @Bean
    public RefreshCookieFactory refreshCookieFactory(JwtSecurityProperties props) {
        return new RefreshCookieFactory(props);
    }

    // ── 기본 사용자 서비스 (호스트가 UserDetailsService 빈을 정의하면 물러난다) ──
    //   example-jpa 가 켜지면 property 로도 꺼져 충돌을 막는다.
    @Bean
    @ConditionalOnMissingBean(UserDetailsService.class)
    @ConditionalOnProperty(name = "jwt-security.example-jpa.enabled", havingValue = "false", matchIfMissing = true)
    public InMemoryUserAccountService inMemoryUserAccountService(PasswordEncoder passwordEncoder) {
        return new InMemoryUserAccountService(passwordEncoder);
    }

    // ── 저장소: 인메모리(기본) ─────────────────────────────────
    @Bean
    @ConditionalOnProperty(name = "jwt-security.store.type", havingValue = "memory", matchIfMissing = true)
    public RefreshTokenStore inMemoryRefreshTokenStore(JwtSecurityProperties props) {
        return new InMemoryRefreshTokenStore(props);
    }

    @Bean
    @ConditionalOnProperty(name = "jwt-security.store.type", havingValue = "memory", matchIfMissing = true)
    public AccessTokenBlacklist inMemoryAccessTokenBlacklist() {
        return new InMemoryAccessTokenBlacklist();
    }

    // ── 저장소: Redis (store.type=redis 일 때만) ───────────────
    @Bean
    @ConditionalOnProperty(name = "jwt-security.store.type", havingValue = "redis")
    public RefreshTokenStore redisRefreshTokenStore(StringRedisTemplate redis, JwtSecurityProperties props) {
        return new RedisRefreshTokenStore(redis, props);
    }

    @Bean
    @ConditionalOnProperty(name = "jwt-security.store.type", havingValue = "redis")
    public AccessTokenBlacklist redisAccessTokenBlacklist(StringRedisTemplate redis) {
        return new RedisAccessTokenBlacklist(redis);
    }

    // ── 토큰 서비스 / 필터 ─────────────────────────────────────
    @Bean
    public TokenService tokenService(JwtProvider jwtProvider, RefreshTokenStore refreshStore,
                                     AccessTokenBlacklist blacklist, UserDetailsService userDetailsService,
                                     JwtSecurityProperties props) {
        return new TokenService(jwtProvider, refreshStore, blacklist, userDetailsService, props);
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtProvider jwtProvider, AccessTokenBlacklist blacklist,
                                                           RestAuthenticationEntryPoint entryPoint,
                                                           JwtSecurityProperties props) {
        return new JwtAuthenticationFilter(jwtProvider, blacklist, entryPoint, props);
    }

    // ── CORS (선택) ───────────────────────────────────────────
    @Bean
    @ConditionalOnProperty(name = "jwt-security.cors.enabled", havingValue = "true")
    public CorsConfigurationSource corsConfigurationSource(JwtSecurityProperties props) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(props.getCors().getAllowedOrigins()); // 와일드카드+credentials 허용
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        config.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // ── 필터 체인 ──────────────────────────────────────────────
    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtAuthenticationFilter,
            RestAuthenticationEntryPoint authenticationEntryPoint,
            RestAccessDeniedHandler accessDeniedHandler,
            JwtSecurityProperties props) throws Exception {

        JwtSecurityProperties.Authorization rules = props.getAuthorization();

        http
                .csrf(csrf -> { if (!props.getCsrf().isEnabled()) csrf.disable(); })
                // cors.enabled=true 면 corsConfigurationSource 빈을 Spring이 자동 인식, 아니면 비활성.
                .cors(cors -> { if (!props.getCors().isEnabled()) cors.disable(); })
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable())
                .authorizeHttpRequests(auth -> {
                    // 1) 역할별(가장 구체적) — hasRole 은 ROLE_ 자동 접두
                    rules.getRoles().forEach((path, role) -> auth.requestMatchers(path).hasRole(role));
                    // 2) 공개
                    if (!rules.getPublicPaths().isEmpty()) {
                        auth.requestMatchers(rules.getPublicPaths().toArray(String[]::new)).permitAll();
                    }
                    // 3) 인증 필요
                    if (!rules.getAuthenticated().isEmpty()) {
                        auth.requestMatchers(rules.getAuthenticated().toArray(String[]::new)).authenticated();
                    }
                    // 4) 그 외 전부 인증 필요
                    auth.anyRequest().authenticated();
                })
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler));

        return http.build();
    }
}
