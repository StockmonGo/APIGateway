package com.pda.APIGateway.jwt;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
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
//
//    //AuthenticationManager Bean 등록
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
//
//        return configuration.getAuthenticationManager();
//    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http) throws Exception{

        http
                .csrf((auth) -> auth.disable())
                .formLogin((auth) -> auth.disable())
                .httpBasic((auth) -> auth.disable())
                .authorizeExchange(auth -> auth.pathMatchers("/api/**")
                        .permitAll()
                        .anyExchange()
                        .permitAll());

//        http
//                .authorizeHttpRequests((auth) -> auth
//                        .requestMatchers("/api/users/signin", "/api/users/join").permitAll()
//                        .requestMatchers("/api/**").hasRole("USER")
//                        .anyRequest().authenticated());


//        http.addFilterBefore(new JWTFilter(jwtUtil),  UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }
}