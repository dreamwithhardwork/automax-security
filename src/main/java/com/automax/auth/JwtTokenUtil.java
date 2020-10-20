package com.automax.auth;

import io.jsonwebtoken.*;
import org.models.core.users.RegisteredUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    public List<String> getAuthoriries(String token){
        Claims claims = getClaimsFromToken(token);
        return (List<String>) claims.get("roles");
    }


    public boolean validate(String token){
        Claims claims= getClaimsFromToken(token);
        Date validity = claims.getExpiration();
        Date current = new Date();
        return current.before(validity);
    }

    public String generateToken(RegisteredUser user) {
        Map<String,Object> claims = new HashMap<>();
        String token = Jwts.builder().setClaims(claims).setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000 *expiry))
                .signWith(SignatureAlgorithm.HS256,secret)
                .compact();
        return token;

    }
}
