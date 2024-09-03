package com.pda.APIGateway.jwt;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;


@EnableWebFluxSecurity
@Configuration
public class SecurityConfig {


    private final JWTUtil jwtUtil;

    SecurityConfig(JWTUtil jwtUtil){
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http) throws Exception{

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .authorizeExchange(auth ->
                        auth
                                .pathMatchers("", "/"
                                        ,"/swagger-ui/index.html"
                                        ,"/api/core/users/signin"
                                        ,"/api/core/v3/api-docs"
                                        ,"/api/stock/v3/api-docs"
                                ,"/api/core/users/join")
                                .permitAll()
                        .pathMatchers("/api/**")
                        .authenticated()
                        .anyExchange()
                        .permitAll()).addFilterBefore(new JWTFilter(jwtUtil), SecurityWebFiltersOrder.AUTHORIZATION)
                        .build();

    }
}