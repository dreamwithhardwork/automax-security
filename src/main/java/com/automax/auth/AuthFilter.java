package com.automax.auth;

import com.automax.auth.provider.UsernamePasswordAuthentication;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.models.core.error.model.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;

@Component
class AuthFilter extends OncePerRequestFilter {


    @Autowired
    JwtTokenUtil jwtTokenUtil;

    @Value("${server.servlet.context-path:/}")
    String contextPath;

    Logger logger = LoggerFactory.getLogger(AuthFilter.class);

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getPathInfo() !=null ? request.getPathInfo() : request.getServletPath();
        return (contextPath.equals("/external") || path.contains("/login") || path.contains("/signup") || path.contains("swagger") || path.contains("api-docs"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.debug(request.getRequestURI());
        String requestTokenHeader = request.getHeader("Authorization");
        String username = null;
        String jwtToken = null;
        try{
            if(requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")){
                jwtToken = requestTokenHeader.substring(7);
                if(jwtTokenUtil.validate(jwtToken)){
                    username = jwtTokenUtil.getUserName(jwtToken);
                }
            }
            if(username!=null && SecurityContextHolder.getContext().getAuthentication() == null){
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,null, new ArrayList<>());
                SecurityContextHolder.getContext().setAuthentication(token);
            }
            filterChain.doFilter(request,response);
        }catch (Exception ex){
            ObjectMapper objectWriter = new ObjectMapper();
            String body=  objectWriter.writeValueAsString(new ErrorResponse(HttpStatus.BAD_REQUEST,ex.getMessage()));
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType("application/json");
            PrintWriter out = response.getWriter();
            out.print(body);
            out.flush();
        }



    }
}
