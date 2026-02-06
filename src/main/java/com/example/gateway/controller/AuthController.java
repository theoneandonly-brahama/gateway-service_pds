package com.example.gateway.controller;

import com.example.gateway.dto.LoginRequest;
import com.example.gateway.dto.RegisterRequest;
import com.example.gateway.dto.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Authentication Controller - Handles login and registration
 *
 * This controller is part of the Gateway and communicates directly with Keycloak
 * It does NOT forward to any service - it handles auth operations itself
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Value("${keycloak.auth-server-url}")
    private String keycloakUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.admin-username}")
    private String adminUsername;

    @Value("${keycloak.admin-password}")
    private String adminPassword;

    private final WebClient webClient;
    private final WebClient.Builder loadBalancedWebClientBuilder;

    public AuthController(
            WebClient.Builder webClientBuilder,
            WebClient.Builder loadBalancedWebClientBuilder
    ) {
        this.webClient = webClientBuilder.build();
        this.loadBalancedWebClientBuilder = loadBalancedWebClientBuilder;
    }

    /**
     * POST /api/auth/login
     *
     * Authenticates user with Keycloak and returns JWT tokens
     */
    @PostMapping("/login")
    public Mono<ResponseEntity<TokenResponse>> login(@RequestBody LoginRequest request) {

        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", clientId);
        formData.add("username", request.getUsername());
        formData.add("password", request.getPassword());
        formData.add("grant_type", "password");

        return webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(formData))
                .retrieve()
                .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                        response -> response.bodyToMono(String.class)
                                .flatMap(errorBody -> Mono.error(new RuntimeException("Authentication failed: " + errorBody))))
                .bodyToMono(Map.class)
                .map(tokenMap -> {
                    TokenResponse tokenResponse = new TokenResponse();
                    tokenResponse.setAccessToken((String) tokenMap.get("access_token"));
                    tokenResponse.setRefreshToken((String) tokenMap.get("refresh_token"));
                    tokenResponse.setExpiresIn((Integer) tokenMap.get("expires_in"));
                    tokenResponse.setTokenType((String) tokenMap.get("token_type"));
                    return ResponseEntity.ok(tokenResponse);
                })
                .onErrorResume(e -> {
                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(new TokenResponse("Authentication failed: " + e.getMessage())));
                });
    }

    /**
     * POST /api/auth/register
     *
     * Creates a new user in Keycloak with the specified role
     * Requires admin credentials to use Keycloak Admin API
     */
    @PostMapping("/register")
    public Mono<ResponseEntity<Map<String, Object>>> register(@RequestBody RegisterRequest request) {

        // Step 1: Get admin token
        return getAdminToken()
                .flatMap(adminToken -> {
                    // Step 2: Create user in Keycloak
                    return createUser(adminToken, request)
                            .flatMap(userId -> {
                                // Step 3: Assign role to user
                                return assignRole(adminToken, userId, request.getRole())
                                        .then(Mono.defer(() -> {
                                            // Step 4: If role is patient, try to link existing patient record
                                            if ("patient".equalsIgnoreCase(request.getRole())) {
                                                return linkPatientRecord(userId, request.getEmail())
                                                        .map(linked -> ResponseEntity.status(HttpStatus.CREATED)
                                                                .body(createSuccessResponse(request.getUsername(), linked)));
                                            } else {
                                                return Mono.just(ResponseEntity.status(HttpStatus.CREATED)
                                                        .body(createSuccessResponse(request.getUsername(), false)));
                                            }
                                        }));
                            });
                })
                .onErrorResume(e -> {
                    Map<String, Object> errorResponse = new HashMap<>();
                    errorResponse.put("error", "Registration failed");
                    errorResponse.put("message", e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse));
                });
    }

    /**
     * POST /api/auth/refresh
     *
     * Refreshes access token using refresh token
     */
    @PostMapping("/refresh")
    public Mono<ResponseEntity<TokenResponse>> refresh(@RequestBody Map<String, String> request) {

        String refreshToken = request.get("refresh_token");
        if (refreshToken == null || refreshToken.isEmpty()) {
            return Mono.just(ResponseEntity.badRequest()
                    .body(new TokenResponse("Refresh token is required")));
        }

        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", clientId);
        formData.add("refresh_token", refreshToken);
        formData.add("grant_type", "refresh_token");

        return webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(Map.class)
                .map(tokenMap -> {
                    TokenResponse tokenResponse = new TokenResponse();
                    tokenResponse.setAccessToken((String) tokenMap.get("access_token"));
                    tokenResponse.setRefreshToken((String) tokenMap.get("refresh_token"));
                    tokenResponse.setExpiresIn((Integer) tokenMap.get("expires_in"));
                    tokenResponse.setTokenType((String) tokenMap.get("token_type"));
                    return ResponseEntity.ok(tokenResponse);
                })
                .onErrorResume(e -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new TokenResponse("Token refresh failed"))));
    }

    // Helper methods

    private Mono<String> getAdminToken() {
        String tokenUrl = keycloakUrl + "/realms/master/protocol/openid-connect/token";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", "admin-cli");
        formData.add("username", adminUsername);
        formData.add("password", adminPassword);
        formData.add("grant_type", "password");

        return webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(Map.class)
                .map(tokenMap -> (String) tokenMap.get("access_token"));
    }

    private Mono<String> createUser(String adminToken, RegisterRequest request) {
        String userUrl = keycloakUrl + "/admin/realms/" + realm + "/users";

        Map<String, Object> userRepresentation = new HashMap<>();
        userRepresentation.put("username", request.getUsername());
        userRepresentation.put("email", request.getEmail());
        userRepresentation.put("firstName", request.getFirstName());
        userRepresentation.put("lastName", request.getLastName());
        userRepresentation.put("enabled", true);
        userRepresentation.put("emailVerified", true);

        // Set password
        Map<String, Object> credential = new HashMap<>();
        credential.put("type", "password");
        credential.put("value", request.getPassword());
        credential.put("temporary", false);
        userRepresentation.put("credentials", Collections.singletonList(credential));

        return webClient.post()
                .uri(userUrl)
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(userRepresentation)
                .exchangeToMono(response -> {
                    if (response.statusCode().is2xxSuccessful()) {
                        // Extract user ID from Location header
                        String location = response.headers().header("Location").get(0);
                        String userId = location.substring(location.lastIndexOf('/') + 1);
                        return Mono.just(userId);
                    } else {
                        return response.bodyToMono(String.class)
                                .flatMap(errorBody -> Mono.error(new RuntimeException("User creation failed: " + errorBody)));
                    }
                });
    }

    private Mono<Void> assignRole(String adminToken, String userId, String roleName) {
        // Default to patient role if not specified
        String role = (roleName != null && !roleName.isEmpty()) ? roleName : "patient";

        // First, get the role ID
        String rolesUrl = keycloakUrl + "/admin/realms/" + realm + "/roles/" + role;

        return webClient.get()
                .uri(rolesUrl)
                .header("Authorization", "Bearer " + adminToken)
                .retrieve()
                .bodyToMono(Map.class)
                .flatMap(roleMap -> {
                    // Assign role to user
                    String assignUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm";

                    Map<String, Object> roleToAssign = new HashMap<>();
                    roleToAssign.put("id", roleMap.get("id"));
                    roleToAssign.put("name", roleMap.get("name"));

                    return webClient.post()
                            .uri(assignUrl)
                            .header("Authorization", "Bearer " + adminToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(Collections.singletonList(roleToAssign))
                            .retrieve()
                            .bodyToMono(Void.class);
                });
    }

    private Map<String, Object> createSuccessResponse(String username, boolean patientLinked) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "User registered successfully");
        response.put("username", username);
        if (patientLinked) {
            response.put("patient_record_linked", "Existing patient record has been linked to your account");
        }
        response.put("next_step", "Please login with your credentials");
        return response;
    }

    /**
     * Try to link an existing patient record to the newly created Keycloak user
     * This is called during patient registration to connect pre-existing medical records
     * Returns true if a record was found and linked, false otherwise
     */
    private Mono<Boolean> linkPatientRecord(String userId, String email) {
        // Call patient service internal endpoint to link the record
        String patientServiceUrl = "lb://PATIENT-SERVICE/internal/link-user";

        Map<String, String> linkRequest = new HashMap<>();
        linkRequest.put("userId", userId);
        linkRequest.put("email", email);

        return loadBalancedWebClientBuilder.build().post()
                .uri(patientServiceUrl)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(linkRequest)
                .retrieve()
                .bodyToMono(Map.class)
                .map(response -> {
                    // Check if a patient was actually linked
                    Boolean linked = (Boolean) response.get("linked");
                    return linked != null && linked;
                })
                .onErrorResume(e -> {
                    // Log the error but don't fail registration if linking fails
                    System.err.println("Failed to link patient record: " + e.getMessage());
                    e.printStackTrace();
                    return Mono.just(false);
                });
    }
}