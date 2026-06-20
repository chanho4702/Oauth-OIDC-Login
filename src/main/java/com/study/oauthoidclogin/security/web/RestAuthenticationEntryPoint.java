package com.study.oauthoidclogin.security.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.study.oauthoidclogin.security.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 인증 실패 → 401 JSON. (필터가 넘긴 구체 코드가 있으면 그대로, 없으면 REQUIRED)
 */
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    public RestAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        Object code = request.getAttribute(JwtAuthenticationFilter.ERROR_CODE_ATTR);
        Object message = request.getAttribute(JwtAuthenticationFilter.ERROR_MESSAGE_ATTR);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "UNAUTHORIZED");
        body.put("code", code != null ? code : "REQUIRED");
        body.put("message", message != null ? message
                : "인증이 필요합니다 — 유효한 Access Token을 Authorization 헤더로 제시하세요");

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getWriter(), body);
    }
}
