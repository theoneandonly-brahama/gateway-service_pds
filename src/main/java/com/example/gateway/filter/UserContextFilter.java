package com.example.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Global filter that runs for every request passing through the gateway
 *
 * This filter extracts user information from the JWT token and adds it as headers
 * so that downstream services (like patient-service) can use it without parsing the token again.
 *
 * Headers added:
 * - X-User-Id: The user's Keycloak subject (sub) claim - unique user identifier
 * - X-User-Name: The user's preferred username
 * - X-User-Email: The user's email address
 * - X-User-Roles: Comma-separated list of roles (e.g., "doctor,user")
 *
 * These headers are trusted by services because they come from the gateway after token verification.
 */
@Component
public class UserContextFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                .map(auth -> (JwtAuthenticationToken) auth)
                .map(jwtAuth -> {
                    Jwt jwt = jwtAuth.getToken();

                    // Extract user information from JWT claims
                    String userId = jwt.getSubject(); // This is the Keycloak user ID
                    String username = jwt.getClaim("preferred_username");
                    String email = jwt.getClaim("email");

                    // Extract roles from authorities (they were converted by KeycloakRoleConverter)
                    List<String> roles = jwtAuth.getAuthorities().stream()
                            .map(authority -> authority.getAuthority().replace("ROLE_", ""))
                            .collect(Collectors.toList());

                    // Add user context to request headers
                    ServerHttpRequest request = exchange.getRequest().mutate()
                            .header("X-User-Id", userId)
                            .header("X-User-Name", username != null ? username : "")
                            .header("X-User-Email", email != null ? email : "")
                            .header("X-User-Roles", String.join(",", roles))
                            .build();

                    return exchange.mutate().request(request).build();
                })
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    @Override
    public int getOrder() {
        // Run this filter early, but after security filters
        return Ordered.LOWEST_PRECEDENCE - 1;
    }
}