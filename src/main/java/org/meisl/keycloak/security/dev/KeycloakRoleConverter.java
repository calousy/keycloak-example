package org.meisl.keycloak.security.dev;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String clientId;

    public KeycloakRoleConverter(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        Collection<String> realmRoles = realmAccess != null
                ? (Collection<String>) realmAccess.getOrDefault("roles", Collections.emptyList())
                : Collections.emptyList();

        // Optional: Client-spezifische Rollen laden
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        Collection<String> clientRoles = Collections.emptyList();
        if (resourceAccess != null && resourceAccess.containsKey(clientId)) {
            Map<String, Object> client = (Map<String, Object>) resourceAccess.get(clientId);
            clientRoles = (Collection<String>) client.getOrDefault("roles", Collections.emptyList());
        }

        // Zusammenführen und in Spring-Authorities konvertieren
        Set<GrantedAuthority> collect = Stream.concat(realmRoles.stream(), clientRoles.stream())
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
        return collect;
    }
}
