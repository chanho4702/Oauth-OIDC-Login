# oauth-oidc-login — OAuth2(6단계) + Google OIDC(7단계) 통합 실습

기존 `jwt-security-module` 의 JWT 인증 모듈을 재사용하고, 그 위에 Spring Security
`oauth2Login`(Authorization Code + PKCE, OIDC) 으로 Google 로그인을 얹은 백엔드.

## 빠른 시작
```powershell
docker compose up -d                       # MySQL(3307)
$env:JAVA_HOME="C:\Program Files\Java\jdk-24"
$env:GOOGLE_CLIENT_ID="...";  $env:GOOGLE_CLIENT_SECRET="..."
.\gradlew.bat bootRun                       # http://localhost:8080
```
데모 로컬 계정(폼 로그인): `user@demo.com/password`, `admin@demo.com/admin`.

## 6단계 — OAuth2 4역할 & Authorization Code + PKCE (시퀀스 분석)

| 역할 | 이 시스템 |
|---|---|
| Resource Owner | 사용자 |
| Client | 이 백엔드(oauth-oidc-login, confidential) |
| Authorization Server | Google (accounts.google.com) |
| Resource Server | Google UserInfo (+ 로그인 후 우리 /api/**) |

시퀀스(Authorization Code + PKCE + OIDC):
1. 브라우저 → `GET /oauth2/authorization/google` — Client 가 인가요청 생성
   (`response_type=code`, `state`, `code_challenge`, `code_challenge_method=S256`).
   STATELESS 라 인가요청은 `OAUTH2_AUTH_REQUEST` 쿠키에 저장(CookieAuthorizationRequestRepository).
2. (front-channel) Google 동의 화면 → 사용자 동의.
3. (front-channel) Google → `GET /login/oauth2/code/google?code=...&state=...` — code 만 전달.
   `state` 를 쿠키의 인가요청과 대조(CSRF 방어).
4. (back-channel) Client → Google `POST /token` : code + client_secret + **code_verifier**.
   Google 이 `code_challenge == SHA256(code_verifier)` 검증(PKCE).
5. Google → Access Token + **ID Token(JWT)** 반환. (OIDC 라 UserInfo 도 조회)
6. CustomOidcUserService: ID Token/UserInfo 표준 클레임 → DB find-or-create.
7. OAuth2LoginSuccessHandler: 우리 서비스 JWT 발급(AT + RT 쿠키) → `/oauth/callback` 리다이렉트.
8. 프론트가 `POST /api/auth/refresh`(RT 쿠키) → AT 획득 → 이후 `Authorization: Bearer <AT>`.

front-channel(브라우저 경유, code 만) vs back-channel(서버↔서버, 토큰 교환)의 분리가 핵심.

## 7단계 — OAuth2 vs OIDC 구조

- **OAuth2(인가)**: 1~5 의 토큰 획득 메커니즘. 결과물 Access Token.
- **OIDC(인증)**: scope 에 `openid` 가 있어 추가되는 신원 계층. 결과물 **ID Token(JWT)**
  + 표준 클레임(iss/sub/aud/exp/email/name) + UserInfo. Spring 이 자동으로 OIDC 모드
  (`OidcUserService`, principal=`OidcUser`)로 전환.
- 한 흐름에 JWT 두 종류:
  - **Google ID Token** — `iss=https://accounts.google.com`. 입구에서 1회. "누구인가"를 Google 이 보증.
  - **우리 Access Token** — `iss=oauth-oidc-login`. 이후 모든 API. 우리 서비스 세션 자격.

## 관찰 포인트(실습 캡처 대상)
- 인가요청 URL 의 `code_challenge`/`state` (브라우저 주소창).
- 서버 로그의 `[OIDC] ID Token claims: ...`.
- MySQL `user_account` 의 GOOGLE 행(provider/provider_id).
