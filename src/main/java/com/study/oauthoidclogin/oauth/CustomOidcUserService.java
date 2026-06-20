package com.study.oauthoidclogin.oauth;

import com.study.oauthoidclogin.user.DbUserDetailsService;
import com.study.oauthoidclogin.user.UserAccount;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.List;

/** 표준 OIDC 사용자 로드 → DB find-or-create → DB role 로 authorities 부여. */
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private static final String PROVIDER = "GOOGLE";

    private final OidcUserService delegate;
    private final DbUserDetailsService provisioning;

    public CustomOidcUserService(OidcUserService delegate, DbUserDetailsService provisioning) {
        this.delegate = delegate;
        this.provisioning = provisioning;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) {
        OidcUser oidcUser = delegate.loadUser(userRequest);

        String sub = oidcUser.getSubject();
        String email = oidcUser.getEmail();
        String name = oidcUser.getFullName();

        UserAccount account = provisioning.provisionOidcUser(PROVIDER, sub, email, name);

        return new DefaultOidcUser(
                List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole())),
                oidcUser.getIdToken(),
                oidcUser.getUserInfo(),
                "sub");
    }
}
