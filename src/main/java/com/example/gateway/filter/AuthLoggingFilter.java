package com.example.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Global filter that logs all authentication and authorization attempts
 *
 * This creates an audit trail of:
 * - Successful authentications
 * - Failed authentications (401)
 * - Authorization failures (403)
 * - User identity and roles for each request
 */
@Component
public class AuthLoggingFilter implements GlobalFilter, Ordered {

    private static final Logger logger = LoggerFactory.getLogger(AuthLoggingFilter.class);
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        String method = exchange.getRequest().getMethod().name();
        String ip = getClientIp(exchange);
        long startTime = System.currentTimeMillis();

        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .defaultIfEmpty(new AnonymousAuth())
                .flatMap(auth -> {
                    String userId = "anonymous";
                    String username = "anonymous";
                    String roles = "none";

                    if (auth instanceof JwtAuthenticationToken) {
                        JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) auth;
                        userId = jwtAuth.getToken().getSubject();
                        username = jwtAuth.getToken().getClaimAsString("preferred_username");
                        roles = jwtAuth.getAuthorities().stream()
                                .map(a -> a.getAuthority().replace("ROLE_", ""))
                                .reduce((a, b) -> a + "," + b)
                                .orElse("none");
                    }

                    final String finalUserId = userId;
                    final String finalUsername = username;
                    final String finalRoles = roles;

                    // Log the request attempt
                    logger.info("AUTH_ATTEMPT | time={} | ip={} | method={} | path={} | user={} | userId={} | roles={}",
                            LocalDateTime.now().format(formatter), ip, method, path, finalUsername, finalUserId, finalRoles);

                    return chain.filter(exchange)
                            .then(Mono.fromRunnable(() -> {
                                long duration = System.currentTimeMillis() - startTime;
                                HttpStatus status = (HttpStatus) exchange.getResponse().    getStatusCode();
                                int statusCode = status != null ? status.value() : 0;

                                // Log the result
                                if (statusCode == 401) {
                                    logger.warn("AUTH_FAILED | time={} | ip={} | method={} | path={} | user={} | status=401 | reason=UNAUTHORIZED | duration={}ms",
                                            LocalDateTime.now().format(formatter), ip, method, path, finalUsername, duration);
                                } else if (statusCode == 403) {
                                    logger.warn("AUTH_DENIED | time={} | ip={} | method={} | path={} | user={} | userId={} | roles={} | status=403 | reason=FORBIDDEN | duration={}ms",
                                            LocalDateTime.now().format(formatter), ip, method, path, finalUsername, finalUserId, finalRoles, duration);
                                } else if (statusCode >= 200 && statusCode < 300) {
                                    logger.info("AUTH_SUCCESS | time={} | ip={} | method={} | path={} | user={} | userId={} | roles={} | status={} | duration={}ms",
                                            LocalDateTime.now().format(formatter), ip, method, path, finalUsername, finalUserId, finalRoles, statusCode, duration);
                                } else if (statusCode >= 400) {
                                    logger.error("AUTH_ERROR | time={} | ip={} | method={} | path={} | user={} | userId={} | status={} | duration={}ms",
                                            LocalDateTime.now().format(formatter), ip, method, path, finalUsername, finalUserId, statusCode, duration);
                                }
                            }));
                });
    }

    private String getClientIp(ServerWebExchange exchange) {
        String ip = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = exchange.getRequest().getRemoteAddress() != null
                    ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
                    : "unknown";
        }
        return ip;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }

    // Dummy class for anonymous authentication
    private static class AnonymousAuth implements org.springframework.security.core.Authentication {
        @Override public Object getCredentials() { return null; }
        @Override public Object getDetails() { return null; }
        @Override public Object getPrincipal() { return "anonymous"; }
        @Override public boolean isAuthenticated() { return false; }
        @Override public void setAuthenticated(boolean isAuthenticated) {}
        @Override public String getName() { return "anonymous"; }
        @Override public java.util.Collection<? extends org.springframework.security.core.GrantedAuthority> getAuthorities() {
            return java.util.Collections.emptyList();
        }
    }
}