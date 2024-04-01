package com.oauth.demo.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Configuration
@Slf4j
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .formLogin(Customizer.withDefaults())
                .oauth2Login(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .build();
        /*Set<String> googleScopes = new HashSet<>();
        googleScopes.add("https://www.googleapis.com/auth/userinfo.email");
        googleScopes.add("https://www.googleapis.com/auth/userinfo.profile");
        OidcUserService googleService = new OidcUserService();
        googleService.setAccessibleScopes(googleScopes);
        return http
                .formLogin(Customizer.withDefaults())
                .oauth2Login(oauth ->
                        oauth
                                .userInfoEndpoint(info -> info
                                        .oidcUserService(googleService)))
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .build();*/
    }

    @Bean
    BCryptPasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService inMemoryUser(){
        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
        var bob = new User("bob", encoder().encode("123"), Collections.emptyList());
        var tom = User.builder()
                .username("tom")
                .password(encoder().encode("1234"))
                .roles("USER")
                .authorities("read")
                .build();
        users.createUser(bob);
        users.createUser(tom);
        return users;
    }

    @Bean
    ApplicationListener<AuthenticationSuccessEvent> successLogger(){
        return event -> {
            log.info("success : {}", event.getAuthentication());
        };
    }
}
