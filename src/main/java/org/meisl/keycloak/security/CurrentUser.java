package org.meisl.keycloak.security;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.server.VaadinSession;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.StandardClaimAccessor;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Service for retrieving the currently authenticated user from the Spring Security context.
 * <p>
 * This service provides methods to safely access user information stored in the authentication principal, supporting
 * principals that implement {@link AppUserPrincipal}. It serves as a bridge between Spring Security's authentication
 * model and the application's user information model.
 * </p>
 * <p>
 * Usage examples (assumes {@code currentUser} has been injected):
 * <p>
 * <!-- spotless:off -->
 * <pre>
 * {@code
 * // Get the current user if available
 * Optional<AppUserInfo> currentUser = currentUser.get();
 *
 * // Get the current user, throwing an exception if not authenticated
 * AppUserInfo user = currentUser.require();
 *
 * // Access user properties
 * String fullName = currentUser.require().getFullName();
 * }
 * </pre>
 * <!-- spotless:on -->
 * </p>
 *
 * @see AppUserInfo The application's user information model
 * @see AppUserPrincipal The principal interface that provides access to user information
 */
public class CurrentUser {

    private static final Logger log = LoggerFactory.getLogger(CurrentUser.class);

    private final SecurityContextHolderStrategy securityContextHolderStrategy;

    /**
     * Creates a new {@code CurrentUser} service for the given {@link SecurityContextHolderStrategy}.
     * <p>
     * This constructor uses the new Spring Security recommendation of accessing the
     * {@link SecurityContextHolderStrategy} as a bean rather than using the static methods of
     * {@link org.springframework.security.core.context.SecurityContextHolder}.
     * </p>
     *
     * @param securityContextHolderStrategy the strategy used to fetch the security context (never {@code null}).
     */
    CurrentUser(SecurityContextHolderStrategy securityContextHolderStrategy) {
        this.securityContextHolderStrategy = requireNonNull(securityContextHolderStrategy);
    }

    /**
     * Returns the currently authenticated user from the security context.
     * <p>
     * This method safely extracts user information from the current security context without throwing exceptions for
     * unauthenticated requests or incompatible principal types.
     * </p>
     * <p>
     * The method expects the authentication principal to implement {@link AppUserPrincipal}. If the principal doesn't
     * implement this interface, a warning is logged and an empty Optional is returned.
     * </p>
     *
     * @return an {@code Optional} containing the current user if authenticated and accessible, or an empty
     * {@code Optional} if there is no authenticated user or the principal doesn't implement
     * {@link AppUserPrincipal}
     * @see #require() For cases where authentication is required
     */
    public Optional<OidcUser> get() {
        return getPrincipal();
    }

    /**
     * Returns the currently authenticated principal from the security context.
     * <p>
     * This method safely extracts the principal from the current security context without throwing exceptions for
     * unauthenticated requests or incompatible principal types.
     * </p>
     * <p>
     * The method expects the authentication principal to implement {@link AppUserPrincipal}. If the principal doesn't
     * implement this interface, a warning is logged and an empty Optional is returned.
     * </p>
     *
     * @return an {@code Optional} containing the current principal if authenticated and accessible, or an empty
     * {@code Optional} if there is no authenticated user or the principal doesn't implement
     * {@link AppUserPrincipal}
     * @see #requirePrincipal() For cases where authentication is required
     */
    public Optional<OidcUser> getPrincipal() {
        return Optional.ofNullable(
                getPrincipalFromAuthentication(securityContextHolderStrategy.getContext().getAuthentication()));
    }

    /**
     * Extracts the principal from the provided authentication object.
     *
     * @param authentication the authentication object from which to extract the principal, may be {@code null}
     * @return the principal if available, or {@code null} if it cannot be extracted
     */
    private @Nullable OidcUser getPrincipalFromAuthentication(@Nullable Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null
            || authentication instanceof AnonymousAuthenticationToken) {
            return null;
        }

        var principal = authentication.getPrincipal();

        if (principal instanceof OidcUser appUserPrincipal) {
            return appUserPrincipal;
        }

        log.warn("Unexpected principal type: {}", principal.getClass().getName());

        return null;
    }

    /**
     * Returns the currently authenticated user from the security context.
     * <p>
     * Unlike {@link #get()}, this method throws an exception if no user is authenticated, making it suitable for
     * endpoints that require authentication.
     * </p>
     *
     * @return the currently authenticated user (never {@code null})
     * @throws AuthenticationCredentialsNotFoundException if there is no authenticated user, or the authenticated principal doesn't implement
     *                                                    {@link AppUserPrincipal}
     */
    public OidcUser require() {
        return get().orElseThrow(() -> new AuthenticationCredentialsNotFoundException("No current user"));
    }

    /**
     * Returns the currently authenticated principal from the security context.
     * <p>
     * Unlike {@link #getPrincipal()}, this method throws an exception if no user is authenticated, making it suitable
     * for endpoints that require authentication.
     * </p>
     *
     * @return the currently authenticated principal (never {@code null})
     * @throws AuthenticationCredentialsNotFoundException if there is no authenticated user, or the authenticated principal doesn't implement
     *                                                    {@link AppUserPrincipal}
     */
    public OidcUser requirePrincipal() {
        return getPrincipal().orElseThrow(() -> new AuthenticationCredentialsNotFoundException("No current user"));
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return getPrincipal().map(OAuth2AuthenticatedPrincipal::getAuthorities).orElse(List.of());
    }

    /**
     * Liefert alle Rollen als Strings (ROLE_admin, ROLE_user, ...)
     */
    public List<String> getRoles() {
        return getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
    }

    /**
     * Liefert alle Claims aus dem OidcUser
     */
    public Map<String, Object> getClaims() {
        return get()
                .map(OidcUser::getClaims)
                .orElse(Map.of());
    }

    public List<String> getKeycloakRoles() {
        return getRoles().stream()
                .map(r -> r.startsWith("ROLE_") ? r.substring(5) : r)
                .toList();
    }

    public Optional<String> getUsername() {
        return get().map(OidcUser::getPreferredUsername);
    }

    public Optional<String> getLastName() {
        return get().map(OidcUser::getFamilyName);
    }

    public Optional<String> getFirstName() {
        return get().map(StandardClaimAccessor::getGivenName);
    }

    public String getPictureUrl() {
        return get().map(StandardClaimAccessor::getPicture).orElse("");
    }

    public Optional<String> getEmail() {
        return get().map(OidcUser::getEmail);
    }

    public String getProfileUrl() {
        return get().map(StandardClaimAccessor::getProfile).orElse(null);
    }

    public String getAccountUrl() {
        return get()
                .map(user -> user.getIssuer().toString() + "/account")
                .orElseThrow(() -> new IllegalStateException("User not authenticated"));
    }

    public String getFullName() {
        return get().map(StandardClaimAccessor::getFullName).orElse("");
    }

    public Optional<String> getAvatar() {
        return get().map(OidcUser::getPicture);
    }

    public Optional<Boolean> isEmailVerified() {
        return get().map(OidcUser::getEmailVerified);
    }

    public void logoutFromKeycloak(UI ui, String redirectUrl) {
        VaadinSession.getCurrent().getSession().invalidate();
        VaadinSession.getCurrent().close();
        ui.getPage().setLocation(require().getIssuer() + "/protocol/openid-connect/logout?post_logout_redirect_uri=" + redirectUrl);
    }


}
