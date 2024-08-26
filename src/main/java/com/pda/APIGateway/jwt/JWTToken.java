package com.pda.APIGateway.jwt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class JWTToken {
        private final Long id;
        private final String role;
}
