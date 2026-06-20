package com.study.oauthoidclogin.security.user;

import jakarta.annotation.PostConstruct;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 기본 인메모리 사용자 저장소. 인프라 없이 바로 동작하라고 데모 계정을 시드한다:
 *   user / password  → ROLE_USER
 *   admin / admin     → ROLE_ADMIN
 *
 * JwtSecurityConfig 에서 @ConditionalOnMissingBean 으로 등록 → 호스트가 자기 UserDetailsService 를
 * 정의하면 이 빈은 물러난다(= DB로 교체 가능).
 */
public class InMemoryUserAccountService implements UserAccountService {

    private record Account(String username, String passwordHash, String role) {}

    private final PasswordEncoder passwordEncoder;
    private final ConcurrentHashMap<String, Account> accounts = new ConcurrentHashMap<>();

    public InMemoryUserAccountService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    void seed() {
        register("user", "password", "USER");
        register("admin", "admin", "ADMIN");
    }

    @Override
    public void register(String username, String rawPassword, String role) {
        if (accounts.containsKey(username)) {
            throw new IllegalArgumentException("이미 존재하는 사용자입니다: " + username);
        }
        accounts.put(username, new Account(username, passwordEncoder.encode(rawPassword), role));
    }

    @Override
    public boolean exists(String username) {
        return accounts.containsKey(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account a = Optional.ofNullable(accounts.get(username))
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username));
        return User.withUsername(a.username())
                .password(a.passwordHash())
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_" + a.role())))
                .build();
    }
}
