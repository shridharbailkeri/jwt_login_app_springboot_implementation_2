package com.unknowncoder.services;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.stream.Collectors;

@Service
public class TokenService {

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;

    public String generateJwt(Authentication authentication) {

        // this will go ahead and get instant at current time
        Instant now = Instant.now();
        // User has Set<Role> authorities i.e list of Roles , each Role has one authority getAuthority() (either user or admin)
        // if you have many roles Set of Roles then plural getAuthorities()
        // authentication.getAuthorities().stream() its looping through all the authorities inside of auth, auth is going to be an
        // authentication object which has all the roles from our user  and then its going to map through them .map(GrantedAuthority::getAuthority)
        // remember our role class implements GrantedAuthority, thats why we are allowed to do this
        // then its going to either user or admin
        // then its going to combine all authorities into a single string delimited by " " .collect(Collectors.joining(" "));
        // next we set up JWT claims set, and this is  the information that the JWTs actually gonna hold itself
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        // issuer meanss "self" indicating that this specific backend or this specific service is issuing this token
        // next we say when we issue this set so we r going to say issued at
        // subject means this is the person who the jwt is going towards which is going to be auth.getname
        // which is going to have the username of the person loging in
        // then we need claim - basically what information is holding, for us this is going to be the roles that we want
        //
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .subject(authentication.getName())
                .claim("roles", scope)
                .build();

        // now use jwt encoder to build jwt from this claims

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        // next go ahead and create a response for a login becaause , we dont just have to pass back the user
        // we also need to pass back a user and the string jwt
    }

}
