package com.example.configuration;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

@AutoConfiguration
public class APIAwareSecurityConfiguration {

    @Bean
    SecurityFilterChain overrideDefaultSpringSecurity(HttpSecurity http) throws Exception {

        http.cors().and()
                .httpBasic().disable()
                .csrf().disable()
                .formLogin().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        return http.build();

    }

    @Bean
    InMemoryUserDetailsManager userDetailsManager() {
        return new InMemoryUserDetailsManager();
    }

    @Configuration
    static class PreAuthConfiguration {
       
        @Autowired
        AuthenticationConfiguration authenticationConfiguration;

        @Bean
        SecurityFilterChain preauthSecurity(HttpSecurity http) throws Exception {


            AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
            
            RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
            filter.setPrincipalRequestHeader("USER_HEADER");
            filter.setAuthenticationManager(authenticationManager);
            filter.setExceptionIfHeaderMissing(false);


            http.addFilter(filter);

            http.authenticationManager(authenticationManager);
            http.authorizeRequests().anyRequest().authenticated();

            return http.build();
        }


        @Bean
        AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> preAuthUserDetailsService() {
    
            return new AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken>() {
                public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token)
                        throws UsernameNotFoundException {
    
                    return new User(token.getName(), "****", Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")));
                };
            };
        }
    
    
        @Bean
        PreAuthenticatedAuthenticationProvider preauthAuthProvider() {
            PreAuthenticatedAuthenticationProvider preauthProvider = new PreAuthenticatedAuthenticationProvider();
            preauthProvider.setPreAuthenticatedUserDetailsService(preAuthUserDetailsService());
    
            return preauthProvider;
        }
    }
    
}
