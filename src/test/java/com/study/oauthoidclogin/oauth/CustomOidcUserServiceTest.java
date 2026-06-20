package com.study.oauthoidclogin.oauth;

import com.study.oauthoidclogin.user.DbUserDetailsService;
import com.study.oauthoidclogin.user.UserAccount;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class CustomOidcUserServiceTest {

    @Test
    void provisionsUserAndAppliesDbRole() {
        // delegate 가 반환할 표준 OidcUser 구성
        OidcIdToken idToken = new OidcIdToken("tok", Instant.now(), Instant.now().plusSeconds(60),
                Map.of("sub", "sub-1", "email", "g@x.com", "name", "G"));
        OidcUser delegateUser = new DefaultOidcUser(List.of(), idToken, "sub");

        OidcUserService delegate = mock(OidcUserService.class);
        when(delegate.loadUser(any(OidcUserRequest.class))).thenReturn(delegateUser);

        DbUserDetailsService provisioning = mock(DbUserDetailsService.class);
        when(provisioning.provisionOidcUser("GOOGLE", "sub-1", "g@x.com", "G"))
                .thenReturn(UserAccount.oidc("g@x.com", "G", "GOOGLE", "sub-1", "ADMIN"));

        CustomOidcUserService service = new CustomOidcUserService(delegate, provisioning);
        OidcUser result = service.loadUser(mock(OidcUserRequest.class));

        verify(provisioning).provisionOidcUser("GOOGLE", "sub-1", "g@x.com", "G");
        assertThat(result.getAuthorities()).extracting("authority").containsExactly("ROLE_ADMIN");
        assertThat(result.getEmail()).isEqualTo("g@x.com");
        assertThat(result.getName()).isEqualTo("sub-1"); // nameAttributeKey="sub"
    }
}
