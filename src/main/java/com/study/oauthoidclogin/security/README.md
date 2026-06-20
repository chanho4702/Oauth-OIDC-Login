# `security/` — 복사해서 쓰는 JWT 시큐리티 모듈

이 폴더(`com.study.oauthoidclogin.security` 패키지)를 **통째로** 당신의 Spring Boot 프로젝트로 복사하면 끝.
(`example_jpa`, `playground` 는 데모/예제이므로 복사 대상이 아니다.)

## 복사 후 3단계

1. **패키지 이동**: `security` 폴더를 당신 base package 아래로 옮긴다.
   예) `com.acme.app.security` — `@SpringBootApplication`(com.acme.app)의 컴포넌트 스캔 범위 안이면 자동 활성화.
   (스캔 범위 밖이면 `@Import(JwtSecurityConfig.class)` 또는 `@ComponentScan` 추가)

2. **의존성**: `build.gradle` 에 아래가 있어야 한다.
   ```gradle
   implementation 'org.springframework.boot:spring-boot-starter-security'
   implementation 'org.springframework.boot:spring-boot-starter-web'
   implementation 'org.springframework.boot:spring-boot-starter-validation'
   implementation 'com.fasterxml.jackson.core:jackson-databind'
   // store.type=redis 를 쓸 때만:
   implementation 'org.springframework.boot:spring-boot-starter-data-redis'
   ```

3. **설정**: `application.yml` 에 `jwt-security:` 블록을 넣는다. (플레이그라운드 "설정 빌더"가 만들어 준다)
   최소 설정:
   ```yaml
   jwt-security:
     secret: ${JWT_SECRET}     # 32바이트 이상
   ```

## 내 사용자 DB 연결하기

모듈은 DB를 모른다. 인증 사용자는 표준 `UserDetailsService` 로 불러온다.
- 기본: `InMemoryUserAccountService` (데모 계정 user/admin 시드)
- **내 빈을 정의하면 그게 이긴다.** `example_jpa/JpaUserAccountService` 가 그 예시다 — 복사해서 도메인에 맞게 고쳐 `@Service` 로 등록하면, 기본 인메모리 빈은 물러난다.

회원가입(`/api/auth/signup`)을 쓰려면 `UserAccountService`(= UserDetailsService + register/exists)를 구현하면 된다. 표준 `UserDetailsService` 만 제공해도 로그인/인가는 완전히 동작한다(가입만 미지원).

## 직접 로그인 컨트롤러를 쓰고 싶다면

`jwt-security.auth-endpoints.enabled: false` 로 내장 API를 끄고, `TokenService` 를 주입해
`issueFor(...)` / `refresh(...)` / `logout(...)` 을 호출하면 된다.

자세한 전체 설명은 프로젝트 루트 `README.md` 참고.
