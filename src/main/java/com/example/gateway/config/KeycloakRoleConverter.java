package com.example.gateway.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Converts Keycloak roles from JWT token to Spring Security GrantedAuthorities
 *
 * Keycloak token structure:
 * {
 *   "realm_access": {
 *     "roles": ["doctor", "user"]
 *   },
 *   "resource_access": {
 *     "patient-service": {
 *       "roles": ["view-patients"]
 *     }
 *   }
 * }
 *
 * We extract realm roles and convert them to Spring Security format: ROLE_doctor, ROLE_user
 */
public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        // Extract realm roles from the token
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");

        if (realmAccess == null || realmAccess.isEmpty()) {
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) realmAccess.get("roles");

        if (roles == null || roles.isEmpty()) {
            return Collections.emptyList();
        }

        // Convert Keycloak roles to Spring Security authorities
        // Keycloak role "doctor" becomes Spring Security authority "ROLE_doctor"
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
    }
}