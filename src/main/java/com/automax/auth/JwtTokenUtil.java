package com.automax.auth;

import io.jsonwebtoken.*;
import org.models.core.users.RegisteredUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.models.core.enums.Roles;

import java.io.Serializable;
import java.util.*;

@Component
public class JwtTokenUtil implements Serializable {
    private static final long serialVersionUID = -2550185165626007488L;

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiry}")
    private Long expiry;


    public Claims getClaimsFromToken(String token) throws ExpiredJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    public String getUserName(String token){
        return getClaimsFromToken(token).getSubject();
    }



    public boolean validate(String token){
        Claims claims= getClaimsFromToken(token);
        Date validity = claims.getExpiration();
        Date current = new Date();
        return current.before(validity);
    }

    public String generateToken(RegisteredUser user) {
        Map<String,Object> claims = new HashMap<>();
        claims.put("roles",user.getRoles());
        String token = Jwts.builder().setClaims(claims).setSubject(user.getEmail()==null?user.getMobile():user.getEmail())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000 *expiry))
                .signWith(SignatureAlgorithm.HS256,secret)
                .compact();
        return token;
    }
    public List<Roles> getRoles(String token){
        Claims claims = getClaimsFromToken(token);
        List<String> roles = (List<String>) claims.get("roles");
        List<Roles> res = new ArrayList<>();
        roles.forEach(r -> {res.add(Roles.valueOf(r));});
        return res;
    }

    public List<GrantedAuthority> getAuthorities(List<Roles> roles){
        List<GrantedAuthority> auth = new ArrayList<>();
        if(roles!=null)
            roles.forEach((roles1 -> auth.add(() -> roles1.name())));
        return auth;
    }
    public List<GrantedAuthority> getAuthorities(String token){
        List<Roles> roles = getRoles(token);
        if(roles==null)
        {
            return  new ArrayList<>();
        }
        return  getAuthorities(roles);
    }
}
