package com.example.ResourceServer.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class RefreshAccessTokenFilter extends OncePerRequestFilter {

    /* Custom filter to return same access token if it is found valid else continue the request  */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            System.out.println("Refresh custom filter");
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            System.out.println("error--->"+ e);
        }
    }
}
