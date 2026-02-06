package com.example.gateway.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
    private Integer expiresIn;
    private String tokenType;
    private String error;

    public TokenResponse() {
    }

    public TokenResponse(String error) {
        this.error = error;
    }

}
