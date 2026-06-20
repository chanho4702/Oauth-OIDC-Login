package com.study.oauthoidclogin.security.user;

import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * ★ 모듈의 사용자 '플러그인 지점'.
 *
 * 모듈 자체는 DB를 모른다. 인증 시 Spring Security 는 표준 {@link UserDetailsService}로 사용자를 불러오는데,
 * 그 구현을 호스트 프로젝트가 갈아끼울 수 있다:
 *   - 기본: {@link InMemoryUserAccountService} (인프라 0, 데모 계정 시드)
 *   - 호스트가 자기 UserDetailsService 빈(예: JPA 기반 example_jpa)을 정의하면 그게 이긴다.
 *
 * register/exists 는 내장 /api/auth/signup 이 쓰는 선택 기능(이걸 구현한 빈이 있을 때만 가입 가능).
 * 표준 UserDetailsService 만 제공해도 인증/인가는 완전히 동작한다.
 */
public interface UserAccountService extends UserDetailsService {

    /** 신규 사용자 등록(가입). role 예: "USER", "ADMIN" (ROLE_ 접두 없이). */
    void register(String username, String rawPassword, String role);

    boolean exists(String username);
}
