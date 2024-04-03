package com.oauth.demo.service;

import com.oauth.demo.model.AppUser;
import com.oauth.demo.model.LoginProvider;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class AppUserService implements UserDetailsService {
    private final BCryptPasswordEncoder encoder;
    Map<String, AppUser> users = new HashMap<>();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return users.get(username);
    }

    @PostConstruct
    public void createHardCodeUser(){
        var tom = AppUser.builder()
                .username("tom")
                .password(encoder.encode("1234"))
                .authorities(List.of(new SimpleGrantedAuthority("read")))
                .build();
        createUser(tom);
    }

    private void createUser(AppUser tom) {
        users.putIfAbsent(tom.getUsername(), tom);
    }

    public OAuth2UserService<OidcUserRequest, OidcUser> oidcLoginHandler() {
        return userRequest -> {
            LoginProvider provider = LoginProvider.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase());
            OidcUserService delegate = new OidcUserService();
            OidcUser oidcUser = delegate.loadUser(userRequest);
            //
            return AppUser.builder()
                    .provider(provider)
                    .imageUrl(oidcUser.getAttribute("picture"))
                    .username(oidcUser.getEmail())
                    .name(oidcUser.getFullName())
                    .email(oidcUser.getEmail())
                    .attributes(oidcUser.getAttributes())
                    .password(encoder.encode(UUID.randomUUID().toString()))
                    .authorities(oidcUser.getAuthorities())
                    .userId(oidcUser.getName())
                    .build();
        };
    }

    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2LoginHandle() {
        return userRequest -> {
            LoginProvider provider = LoginProvider.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase());
            DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
            OAuth2User oAuth2User = delegate.loadUser(userRequest);
            //
            return AppUser.builder()
                    .password(encoder.encode(UUID.randomUUID().toString()))
                    .userId(oAuth2User.getName())
                    .username(oAuth2User.getAttribute("login"))
                    .name(oAuth2User.getAttribute("login"))
                    .imageUrl(oAuth2User.getAttribute("avatar_url"))
                    .provider(provider)
                    .attributes(oAuth2User.getAttributes())
                    .authorities(oAuth2User.getAuthorities())
                    .build();
        };
    }
}
