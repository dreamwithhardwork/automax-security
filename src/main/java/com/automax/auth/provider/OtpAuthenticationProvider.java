package com.automax.auth.provider;

import com.automax.auth.JwtTokenUtil;
import org.models.core.dao.OtpRepository;
import org.models.core.dao.UsersRepository;
import org.models.core.domain.Otp;
import org.models.core.users.RegisteredUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class OtpAuthenticationProvider implements AuthenticationProvider {


    @Autowired
    OtpRepository otpRepository;

    @Autowired
    UsersRepository usersRepository;

    @Autowired
    JwtTokenUtil jwtTokenUtil;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String otp = (String) authentication.getCredentials();

        Otp otpObject = otpRepository.findFirstByUsername(username);
        Date now = new Date();
        Boolean valid = (otpObject!=null  && ((now.getTime() - otpObject.getDate().getTime())/1000)<90);

        if(!valid){
           throw  new BadCredentialsException("Otp validation failed");
        }
        RegisteredUser user= usersRepository.findOneByEmail(username);
        if(user ==null){
            user = usersRepository.findOneByMobile(username);
        }
        if(user==null){
            throw new BadCredentialsException("No user found");
        }

        if (bCryptPasswordEncoder.matches(otp, otpObject.getOtp())) {
            OtpAuthentication auth = new OtpAuthentication(username, bCryptPasswordEncoder.encode(user.getPassword()));
            auth.setDetails(user);
            return auth;
        }

        throw new BadCredentialsException("password or otp did not match");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OtpAuthentication.class.equals(authentication);
    }
}
