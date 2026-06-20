package com.study.oauthoidclogin.user;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class UserAccountRepositoryTest {

    @Autowired UserAccountRepository repository;

    @Test
    void findsByEmailAndByProviderId() {
        repository.save(UserAccount.oidc("a@x.com", "A", "GOOGLE", "sub-123", "USER"));

        assertThat(repository.findByEmail("a@x.com")).isPresent();
        assertThat(repository.findByProviderAndProviderId("GOOGLE", "sub-123")).isPresent();
        assertThat(repository.existsByEmail("a@x.com")).isTrue();
        assertThat(repository.findByEmail("none@x.com")).isEmpty();
    }
}
