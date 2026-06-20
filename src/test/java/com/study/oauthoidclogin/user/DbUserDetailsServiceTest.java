package com.study.oauthoidclogin.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class DbUserDetailsServiceTest {

    PasswordEncoder encoder = new BCryptPasswordEncoder();
    UserAccountRepository repo;
    DbUserDetailsService service;

    @BeforeEach
    void setup() {
        repo = mock(UserAccountRepository.class);
        when(repo.save(any(UserAccount.class))).thenAnswer(i -> i.getArgument(0));
        service = new DbUserDetailsService(repo, encoder);
    }

    @Test
    void registerStoresLocalUserWithBcryptHash() {
        when(repo.existsByEmail("u@x.com")).thenReturn(false);
        service.register("u@x.com", "password", "USER");

        verify(repo).save(argThat(u ->
                u.getProvider().equals("LOCAL")
                && encoder.matches("password", u.getPasswordHash())
                && u.getRole().equals("USER")));
    }

    @Test
    void loadUserByUsernameMapsRoleWithPrefix() {
        when(repo.findByEmail("u@x.com"))
                .thenReturn(Optional.of(UserAccount.local("u@x.com", encoder.encode("password"), "ADMIN")));

        UserDetails details = service.loadUserByUsername("u@x.com");
        assertThat(details.getUsername()).isEqualTo("u@x.com");
        assertThat(details.getAuthorities()).extracting("authority").containsExactly("ROLE_ADMIN");
    }

    @Test
    void loadMissingUserThrows() {
        when(repo.findByEmail("none@x.com")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.loadUserByUsername("none@x.com"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void provisionCreatesOnFirstLoginThenReuses() {
        Map<String, UserAccount> db = new HashMap<>();
        when(repo.findByProviderAndProviderId("GOOGLE", "sub-1"))
                .thenAnswer(i -> Optional.ofNullable(db.get("sub-1")));
        when(repo.save(any(UserAccount.class))).thenAnswer(i -> {
            UserAccount u = i.getArgument(0);
            db.put(u.getProviderId(), u);
            return u;
        });

        UserAccount first = service.provisionOidcUser("GOOGLE", "sub-1", "g@x.com", "G");
        UserAccount second = service.provisionOidcUser("GOOGLE", "sub-1", "g@x.com", "G");

        assertThat(first.getProvider()).isEqualTo("GOOGLE");
        assertThat(first.getRole()).isEqualTo("USER");
        verify(repo, times(1)).save(any(UserAccount.class)); // 두 번째는 재사용
    }
}
