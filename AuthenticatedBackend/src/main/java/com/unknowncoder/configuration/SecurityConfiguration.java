package com.unknowncoder.configuration;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.unknowncoder.utils.RSAKeyProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
public class SecurityConfiguration {

    private final RSAKeyProperties keys;

    public SecurityConfiguration(RSAKeyProperties keys) {
        this.keys = keys;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Authentication manager -> this is how spring security actually go through and figure out whether or not
    // this user is actually supposed to be authenticated or not
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService detailsService) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        // set this daoAuthenticationProvider to user service that way where and how to look for the user to authenticate
        daoAuthenticationProvider.setUserDetailsService(detailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder()); // if u dont add this u get error
        return new ProviderManager(daoAuthenticationProvider);
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(antMatcher("/auth/**")).permitAll();
                    auth.requestMatchers(antMatcher("/admin/**")).hasRole("ADMIN"); // has role part is only going to look for uppercase ADMIN
                    // however the authentication manager is going to look for ROLE_ADMIN, this is why we had to set up the JwtAuthenticationConverter
                    //
                    auth.requestMatchers(antMatcher("/user/**")).hasAnyRole("ADMIN", "USER");
                    auth.anyRequest().authenticated();
                });
                // to show our userservice is being used properly as user details service
                // pass in a user name and password through a http form and we will authenticate that way
                //.httpBasic(withDefaults()) // so what happens is whenever you make a request to a user controller http://localhost:8000/user/ i.e helloUserController()
                // security config will say hay this needs to be authenticated because auth.anyRequest().authenticated()
                // it says hay ok our Authmanager is using UserDetailsService and then enters UserDetailsService i.e UserService
                // then checks user name and password from database and then we did get the user back and then enters inside user controller
                // or stays at UserService and then comes out of it by throwing UsernameNotFoundException
                // we dont have to pass username and password for every single request in post man instead
                // send in username and password just once and have the application send back a token for us and then put
                // that into a AuthToken or a Bearer Token as we see in Postman , that was it is easier and that way backend doesnt have to hold
                // the state either
                //// next is tell spring security to actually use the oauth resource server and to read jwts go to security filter chain so get rid of http basic
        http
                .oauth2ResourceServer() // its going to configure a oauth resource server for us and its going to
                    .jwt()
                    .jwtAuthenticationConverter(jwtAuthenticationConverter()); // pass in the jwt authentication converter that we set up below
                // know to check for jwt token, now every time we send a request that needs to be authenticated its going to look inside the
                // bearer token authentication header and look for a token and then using encoder and decoder its going to know how to actually for that
                // and then using the public and private keys , its going to know whether or not this is proper or not
                // now after setting this up we need to go ahead and make our code be able to create our jwt token
                // to send back to the client and actually decode them if we ever need that , now we need a service to actually create these jwts
        http
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    // method that returns jwt decoder , for taking in jwt and get the data out of it (token)
    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(keys.getPublicKey()).build();
    }

    // will take some information bundle it up and sign it with our public and private key and then spit it out
    // for us
    @Bean
    public JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(keys.getPublicKey()).privateKey(keys.getPrivateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

    // to make user not access admin level and admin not access user level
    // because of what we named our roles in our table we just called them role
    // we have to convert all the names inside of the claim roles into role underscore role
    // so for example if its a role user instead of just having the role user we need to change this to
    // role underscore user
    // to do this we need jwt granted authorities converter
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // go ahead and set the name of the claim that is JWT granted authorities converter is going to look for
        // in our case we set the roles of the user in a claim name callled roles
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        // now we need to tell the converter , we want to rename each role into
        // the spring security convention is to use roll underscore this is why
        // we obviously named our roles like user or admin because inside of our table
        // we dont want role underscore everything , se we need to convert these
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        // now we need to create a new jwt authentication converter to go ahead and call our
        // jwt granted authorities converter and this will go ahead and actually take those roles and append
        // roll name and return a new authority for us to use
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
        // recap -> whenever we create a JWT token that gets decoded by the backend its going to have a claim called roles
        // the claim , the claim with roles is going to hold all the roles that this user has , so basically are they user?
        // are they admin? are they employee or guest so on , the problem with this is that by default
        // what spring is going to look for whenever its decoding these and authenticating people is its going to
        // look for the "role underscore", so currently our roles do not have role underscore so
        // then spring security will not know how to match a user against the role so this jwt granted authorities converter
        // is going to go through , look at that token that it created and convert all of our roles inside of our role claim
        // into role underscore and  then this jwt converter will go ahead and spit out a new token
        // that way spring security can be able to actually tell whats going on , to be able to actually use this we need to
        // set this up inside oauth2 resource server inside our filter chain , we r also going to do a little bit of refactoring
        // inside the filter chain

    }


}
