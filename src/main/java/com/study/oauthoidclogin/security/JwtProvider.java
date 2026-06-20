package com.study.oauthoidclogin.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * JWT를 라이브러리 없이 직접 발급/검증한다 (HS256).
 *   base64url(header) . base64url(payload) . base64url(HMAC-SHA256 서명)
 *
 * 모든 파라미터(secret, issuer, AT 수명)는 JwtSecurityProperties 에서 온다 →
 * 코드 수정 없이 application.yml 로만 동작이 바뀐다.
 */
@Component
public class JwtProvider {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private final ObjectMapper objectMapper;
    private final JwtSecurityProperties props;

    public JwtProvider(ObjectMapper objectMapper, JwtSecurityProperties props) {
        this.objectMapper = objectMapper;
        this.props = props;
    }

    /** 토큰 발급. extraClaims 로 role 등 추가 정보를 담는다. jti(고유 ID)는 항상 부여(블랙리스트 키). */
    public String issue(String subject, Map<String, Object> extraClaims) {
        long now = Instant.now().getEpochSecond();
        long exp = now + props.getAccessToken().getValiditySeconds();

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "HS256");
        header.put("typ", "JWT");

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", props.getIssuer());
        payload.put("sub", subject);
        payload.put("iat", now);
        payload.put("exp", exp);
        payload.put("jti", UUID.randomUUID().toString());
        if (extraClaims != null) {
            payload.putAll(extraClaims);
        }

        String signingInput = base64UrlJson(header) + "." + base64UrlJson(payload);
        return signingInput + "." + sign(signingInput);
    }

    /** 검증: 형식 → 서명 → 만료. 통과 시 payload(클레임 Map) 반환, 실패 시 JwtException. */
    public Map<String, Object> verify(String token) {
        if (token == null || token.isBlank()) {
            throw new JwtException(JwtException.Code.MALFORMED, "토큰이 비어 있습니다");
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new JwtException(JwtException.Code.MALFORMED,
                    "JWT는 점(.)으로 구분된 3부분이어야 합니다 (현재 " + parts.length + "부분)");
        }

        String signingInput = parts[0] + "." + parts[1];
        boolean signatureOk = MessageDigest.isEqual(
                sign(signingInput).getBytes(StandardCharsets.UTF_8),
                parts[2].getBytes(StandardCharsets.UTF_8));
        if (!signatureOk) {
            throw new JwtException(JwtException.Code.BAD_SIGNATURE,
                    "서명이 일치하지 않습니다 — 위조되었거나 키가 다릅니다");
        }

        Map<String, Object> payload = decodePayload(parts[1]);
        long exp = ((Number) payload.getOrDefault("exp", 0)).longValue();
        if (Instant.now().getEpochSecond() >= exp) {
            throw new JwtException(JwtException.Code.EXPIRED, "토큰이 만료되었습니다");
        }
        return payload;
    }

    /** payload 만 디코드(검증 없이 내용 열람용). */
    public Map<String, Object> decodePayload(String payloadPart) {
        try {
            //noinspection unchecked
            return objectMapper.readValue(URL_DECODER.decode(payloadPart), Map.class);
        } catch (Exception e) {
            throw new JwtException(JwtException.Code.MALFORMED, "페이로드 해석 실패: " + e.getMessage());
        }
    }

    private String base64UrlJson(Map<String, Object> map) {
        try {
            return URL_ENCODER.encodeToString(objectMapper.writeValueAsBytes(map));
        } catch (Exception e) {
            throw new IllegalStateException("JSON 직렬화 실패", e);
        }
    }

    private String sign(String signingInput) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(props.getSecret().getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            return URL_ENCODER.encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 서명 실패", e);
        }
    }
}
