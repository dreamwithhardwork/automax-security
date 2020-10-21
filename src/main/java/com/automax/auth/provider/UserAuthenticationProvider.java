package com.automax.auth.provider;

import com.automax.auth.JwtTokenUtil;
import org.models.core.dao.UsersRepository;
import org.models.core.users.RegisteredUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class UserAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    UsersRepository usersRepository;

    @Autowired
    JwtTokenUtil jwtTokenUtil;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();


        RegisteredUser user= usersRepository.findOneByEmail(username);
        if(user ==null){
            user = usersRepository.findOneByMobile(username);
        }
        if(user==null){
            throw new BadCredentialsException(":(");
        }

        if (bCryptPasswordEncoder.matches(password, user.getPassword())) {
            UsernamePasswordAuthentication auth = new UsernamePasswordAuthentication(username, password);
            auth.setDetails(user);
            return auth;
        }

        throw new BadCredentialsException(":(");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthentication.class.equals(authentication);
    }
}
