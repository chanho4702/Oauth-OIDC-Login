package com.study.oauthoidclogin.user;

import jakarta.persistence.*;

/** OIDC/로컬 사용자 공용 테이블. provider 로 출처 구분. subject(username)=email. */
@Entity
@Table(name = "user_account",
        uniqueConstraints = @UniqueConstraint(columnNames = "email"))
public class UserAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    private String name;

    @Column(nullable = false)
    private String provider;        // "LOCAL" | "GOOGLE"

    private String providerId;      // OIDC sub (LOCAL 이면 null)

    private String passwordHash;    // OIDC 사용자는 null

    @Column(nullable = false)
    private String role;            // "USER" | "ADMIN"

    protected UserAccount() {}      // JPA

    private UserAccount(String email, String name, String provider,
                        String providerId, String passwordHash, String role) {
        this.email = email;
        this.name = name;
        this.provider = provider;
        this.providerId = providerId;
        this.passwordHash = passwordHash;
        this.role = role;
    }

    public static UserAccount local(String email, String passwordHash, String role) {
        return new UserAccount(email, email, "LOCAL", null, passwordHash, role);
    }

    public static UserAccount oidc(String email, String name, String provider,
                                   String providerId, String role) {
        return new UserAccount(email, name, provider, providerId, null, role);
    }

    public Long getId()            { return id; }
    public String getEmail()       { return email; }
    public String getName()        { return name; }
    public String getProvider()    { return provider; }
    public String getProviderId()  { return providerId; }
    public String getPasswordHash(){ return passwordHash; }
    public String getRole()        { return role; }

    public void setName(String name)               { this.name = name; }
    public void setPasswordHash(String passwordHash){ this.passwordHash = passwordHash; }
    public void setRole(String role)               { this.role = role; }
}
