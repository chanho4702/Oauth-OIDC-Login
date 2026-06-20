package com.study.oauthoidclogin.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ★ 이 모듈의 단일 설정 원천. application.yml 의 `jwt-security.*` 를 통째로 담는다.
 *
 * 설계 의도: "코드는 건드리지 않고 application.yml 만으로 동작을 바꾼다."
 *   - 어떤 경로를 열고/막을지, 토큰 수명, 쿠키 속성, Redis 사용 여부, 내장 로그인 API 노출 여부까지
 *     전부 여기서 결정된다. SecurityConfig/필터/스토어는 이 값을 읽어 자기 행동을 정한다.
 *
 * 플레이그라운드의 "설정 빌더"가 만들어 주는 yml 이 정확히 이 구조다.
 */
@Data
@ConfigurationProperties(prefix = "jwt-security")
public class JwtSecurityProperties {

    /** HMAC-SHA256 서명 키. 32바이트(256bit) 이상 권장. 운영에선 환경변수/시크릿으로 주입. */
    private String secret = "change-me-please-this-demo-secret-must-be-at-least-32-bytes-long!";

    /** 토큰 발급자 식별자 (payload 의 iss). */
    private String issuer = "jwt-security";

    private Store store = new Store();
    private AccessToken accessToken = new AccessToken();
    private RefreshToken refreshToken = new RefreshToken();
    private Blacklist blacklist = new Blacklist();
    private Authorization authorization = new Authorization();
    private Cors cors = new Cors();
    private Csrf csrf = new Csrf();
    private AuthEndpoints authEndpoints = new AuthEndpoints();

    /** 리프레시 토큰/블랙리스트를 어디에 저장할지. memory(기본) | redis */
    @Data
    public static class Store {
        /** memory | redis */
        private String type = "memory";
    }

    /** Access Token(JWT, 자체검증). 항상 Authorization: Bearer 헤더로 오간다(표준). */
    @Data
    public static class AccessToken {
        /** AT 유효시간(초). 짧게. 실무 5~15분. */
        private long validitySeconds = 900;
    }

    /** Refresh Token(불투명 랜덤 문자열, 서버가 기억). 길게. */
    @Data
    public static class RefreshToken {
        /** RT 기능 자체를 끌 수도 있다(순수 AT-only 모드). */
        private boolean enabled = true;
        /** RT 유효시간(초). 실무 수일~수주. 기본 14일. */
        private long validitySeconds = 1_209_600;
        /** refresh 할 때마다 새 RT 발급 + 옛 RT 폐기(권장). */
        private boolean rotation = true;
        /** 폐기된 RT 재사용 시 패밀리 전체 무효화(탈취 방어). */
        private boolean reuseDetection = true;
        private Cookie cookie = new Cookie();

        /** RT를 담아 보내는 HttpOnly 쿠키 설정. */
        @Data
        public static class Cookie {
            private String name = "REFRESH_TOKEN";
            /** JS(document.cookie)가 못 읽게 → XSS 방어 핵심. */
            private boolean httpOnly = true;
            /** https 에서만 전송. 운영 필수 true, localhost 실습 false. */
            private boolean secure = false;
            /** Strict | Lax | None — CSRF 1차 방어. */
            private String sameSite = "Strict";
            /** 이 경로 이하 요청에만 쿠키가 실린다(노출 최소화). */
            private String path = "/api/auth";
        }
    }

    /** Access Token jti 블랙리스트 — 로그아웃/탈취 시 만료 전 AT도 즉시 무효화. */
    @Data
    public static class Blacklist {
        private boolean enabled = true;
    }

    /**
     * 경로별 인가 규칙. SecurityConfig 의 authorizeHttpRequests 가 이 순서로 적용한다:
     *   roles(가장 구체적) → public → authenticated → 그 외(anyRequest)
     */
    @Data
    public static class Authorization {
        /** 인증 없이 통과(로그인/정적/공개 API 등). */
        private List<String> publicPaths = new ArrayList<>(List.of(
                "/", "/index.html", "/playground.js", "/playground.css",
                "/favicon.ico", "/error", "/api/auth/**", "/api/playground/**"));
        /** 인증만 되면 통과. */
        private List<String> authenticated = new ArrayList<>(List.of("/api/**"));
        /** 경로 → 필요 역할. 예: {"/api/admin/**": "ADMIN"}. (hasRole — ROLE_ 자동 접두) */
        private Map<String, String> roles = new LinkedHashMap<>(Map.of("/api/admin/**", "ADMIN"));
    }

    @Data
    public static class Cors {
        private boolean enabled = false;
        private List<String> allowedOrigins = new ArrayList<>(List.of("*"));
    }

    @Data
    public static class Csrf {
        /** REST + 토큰 기반이면 보통 false. 세션/폼 쓰면 true 고려. */
        private boolean enabled = false;
    }

    /** 내장 인증 엔드포인트(/api/auth/login·refresh·logout·signup) 노출 여부. */
    @Data
    public static class AuthEndpoints {
        private boolean enabled = true;
    }
}
