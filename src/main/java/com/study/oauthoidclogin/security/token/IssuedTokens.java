package com.study.oauthoidclogin.security.token;

/**
 * 로그인/갱신 결과. AccessToken은 본문으로, refreshTokenId는 쿠키로 나간다(null이면 RT 비활성).
 *
 * @param accessToken             JWT(a.b.c)
 * @param refreshTokenId          RT 본체(쿠키로 내려보낼 값). RT 비활성 시 null
 * @param refreshTokenFingerprint RT 지문(화면 표시용, 본체 아님)
 * @param accessTokenExpiresIn    AT 남은 수명(초)
 * @param refreshTokenExpiresIn   RT 남은 수명(초)
 */
public record IssuedTokens(
        String accessToken,
        String refreshTokenId,
        String refreshTokenFingerprint,
        long accessTokenExpiresIn,
        long refreshTokenExpiresIn
) {
}
