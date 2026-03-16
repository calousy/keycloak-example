package org.meisl.keycloak.security.dev;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class KeycloakOidcUserService extends OidcUserService {

    @Autowired
    private JwtDecoder jwtDecoder;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) {
        OidcUser oidcUser = super.loadUser(userRequest);

        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

        // Access Token auslesen
        String tokenValue = userRequest.getAccessToken().getTokenValue();

        // Claims decodieren
        Jwt jwt = jwtDecoder.decode(tokenValue);
        Map<String, Object> accessTokenClaims = jwt.getClaims();


        // Realm-Rollen
        Map<String, Object> realmAccess =
                (Map<String, Object>) accessTokenClaims.get("realm_access");
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            List<String> roles = (List<String>) realmAccess.get("roles");
            mappedAuthorities.addAll(roles.stream()
                    .map(r -> new SimpleGrantedAuthority("ROLE_" + r.toUpperCase()))
                    .toList());
        }

        // Client-Rollen
        Map<String, Object> resourceAccess = (Map<String, Object>) accessTokenClaims.get("resource_access");
        if (resourceAccess != null) {
            resourceAccess.forEach((clientId, access) -> {
                Map<String, Object> clientMap = (Map<String, Object>) access;
                if (clientMap.containsKey("roles")) {
                    List<String> roles = (List<String>) clientMap.get("roles");
                    mappedAuthorities.addAll(roles.stream()
                            .map(r -> new SimpleGrantedAuthority("ROLE_" + clientId.toUpperCase() + "_" + r.toUpperCase()))
                            .toList());
                }
            });
        }

        return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }
}
