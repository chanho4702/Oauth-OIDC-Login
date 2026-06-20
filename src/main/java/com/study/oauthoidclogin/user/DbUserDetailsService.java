package com.study.oauthoidclogin.user;

import com.study.oauthoidclogin.security.user.UserAccountService;
import jakarta.annotation.PostConstruct;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

/** DB(JPA) 기반 사용자 서비스: 폼 로그인 + 가입 + 데모 시드 + OIDC provisioning. */
@Service
public class DbUserDetailsService implements UserAccountService {

    /** OIDC 사용자는 비번이 없다 → BCrypt 로 절대 매칭되지 않는 placeholder. */
    static final String NO_PASSWORD = "OIDC_NO_PASSWORD";

    private final UserAccountRepository repository;
    private final PasswordEncoder passwordEncoder;

    public DbUserDetailsService(UserAccountRepository repository, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    void seedDemoAccounts() {
        if (!repository.existsByEmail("user@demo.com"))  register("user@demo.com", "password", "USER");
        if (!repository.existsByEmail("admin@demo.com")) register("admin@demo.com", "admin", "ADMIN");
    }

    @Override
    public void register(String email, String rawPassword, String role) {
        if (repository.existsByEmail(email)) {
            throw new IllegalArgumentException("이미 존재하는 사용자입니다: " + email);
        }
        repository.save(UserAccount.local(email, passwordEncoder.encode(rawPassword), role));
    }

    @Override
    public boolean exists(String email) {
        return repository.existsByEmail(email);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserAccount u = repository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + email));
        String password = u.getPasswordHash() != null ? u.getPasswordHash() : NO_PASSWORD;
        return User.withUsername(u.getEmail())
                .password(password)
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_" + u.getRole())))
                .build();
    }

    /** OIDC 로그인: (provider, providerId) 로 find-or-create. 최초 ROLE_USER 자동 가입. */
    public UserAccount provisionOidcUser(String provider, String providerId, String email, String name) {
        return repository.findByProviderAndProviderId(provider, providerId)
                .orElseGet(() -> repository.save(
                        UserAccount.oidc(email, name, provider, providerId, "USER")));
    }
}
