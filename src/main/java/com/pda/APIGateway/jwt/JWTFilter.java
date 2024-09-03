package com.pda.APIGateway.jwt;

import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;

import java.util.List;

public class JWTFilter implements WebFilter {

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authorization = exchange.getRequest().getHeaders().getFirst("Authorization");

        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        String token = authorization.substring(7);

        if (jwtUtil.isExpired(token)) {
            return chain.filter(exchange);
        }

        Long id = jwtUtil.getId(token);
        String role = jwtUtil.getRole(token);

        JWTToken jwtToken = new JWTToken(id, role);
        Authentication authToken = new UsernamePasswordAuthenticationToken(jwtToken, null, List.of(new SimpleGrantedAuthority(role)));

        exchange.getResponse().getHeaders().set("travelerId", String.valueOf(id));
        return chain.filter(exchange)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authToken));
    }
}
