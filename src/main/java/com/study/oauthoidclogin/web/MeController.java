package com.study.oauthoidclogin.web;

import com.study.oauthoidclogin.user.UserAccount;
import com.study.oauthoidclogin.user.UserAccountRepository;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.util.LinkedHashMap;
import java.util.Map;

/** 보호 리소스: 인증된 사용자의 신원(+OIDC 출처) 반환. */
@RestController
public class MeController {

    private final UserAccountRepository repository;

    public MeController(UserAccountRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/api/me")
    public Map<String, Object> me(Authentication authentication) {
        UserAccount u = repository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자 없음"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", u.getEmail());
        body.put("name", u.getName());
        body.put("provider", u.getProvider());
        body.put("sub", u.getProviderId());
        body.put("role", u.getRole());
        return body;
    }
}
