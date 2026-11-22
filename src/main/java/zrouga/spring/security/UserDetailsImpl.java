package zrouga.spring.security;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class UserDetailsImpl implements UserDetails {

    private static final long serialVersionUID = 1L;

    private static final String ROLE_PREFIX = "ROLE_";

    private Long id;

    private String username;

    private String email;

    @JsonIgnore
    private String password;

    private boolean enabled;

    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(Long id, String username, String email, String password,
            Collection<? extends GrantedAuthority> authorities) {
        this(id, username, email, password, authorities, true);
    }

    private UserDetailsImpl(Long id, String username, String email, String password,
            Collection<? extends GrantedAuthority> authorities, boolean enabled) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
        this.enabled = enabled;
    }

    /**
     * Construit un principal à partir d'un utilisateur du projet hôte.
     *
     * @param user l'utilisateur (rôles illimités, statut optionnel)
     * @return le principal correspondant
     */
    public static UserDetailsImpl build(AuthUser user) {
        boolean enabled = user.getStatus() == null || user.getStatus();
        return new UserDetailsImpl(user.getId(), user.getEmail(), user.getEmail(), user.getPassword(),
                authoritiesFrom(user.getRoles()), enabled);
    }

    /**
     * Construit un principal directement depuis les claims d'un JWT validé
     * (aucune requête supplémentaire vers le projet hôte).
     *
     * @param id     claim {@code id}
     * @param email  claim {@code email} / {@code sub}
     * @param status claim {@code status} ({@code null} = actif)
     * @param roles  claim {@code roles}
     * @return le principal correspondant
     */
    public static UserDetailsImpl buildFromToken(Long id, String email, Boolean status, List<String> roles) {
        boolean enabled = status == null || status;
        return new UserDetailsImpl(id, email, email, null, authoritiesFrom(roles), enabled);
    }

    private static List<GrantedAuthority> authoritiesFrom(List<String> roles) {
        if (roles == null) {
            return List.of();
        }
        return roles.stream()
                .filter(Objects::nonNull)
                .map(role -> role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UserDetailsImpl user = (UserDetailsImpl) o;
        return Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
