package com.study.oauthoidclogin.web;

import com.study.oauthoidclogin.user.UserAccount;
import com.study.oauthoidclogin.user.UserAccountRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class MeControllerTest {

    @Test
    void returnsIdentityWithProviderAndSub() {
        UserAccountRepository repo = mock(UserAccountRepository.class);
        when(repo.findByEmail("g@x.com"))
                .thenReturn(Optional.of(UserAccount.oidc("g@x.com", "G", "GOOGLE", "sub-9", "USER")));
        MeController controller = new MeController(repo);
        Authentication auth = new UsernamePasswordAuthenticationToken("g@x.com", null, List.of());

        Map<String, Object> body = controller.me(auth);

        assertThat(body).containsEntry("email", "g@x.com")
                .containsEntry("provider", "GOOGLE")
                .containsEntry("sub", "sub-9")
                .containsEntry("role", "USER")
                .containsEntry("name", "G");
    }
}
