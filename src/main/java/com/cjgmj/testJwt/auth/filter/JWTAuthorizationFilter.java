package com.cjgmj.testJwt.auth.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.cjgmj.testJwt.auth.service.JWTService;
import com.cjgmj.testJwt.auth.service.LogoutService;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private JWTService jwtService;
	private LogoutService logoutService;

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService,
			LogoutService logoutService) {
		super(authenticationManager);
		this.jwtService = jwtService;
		this.logoutService = logoutService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String header = request.getHeader(JWTService.HEADER_STRING);

		if (!requiresAutentication(header)) {
			chain.doFilter(request, response);
			return;
		}

		if (!jwtService.validate(header) || logoutService.existsByUsername(jwtService.getUsername(header))) {
			chain.doFilter(request, response);
			return;
		}

		UsernamePasswordAuthenticationToken authentication = null;
		if (jwtService.validate(header)) {
			authentication = new UsernamePasswordAuthenticationToken(jwtService.getUsername(header), null,
					jwtService.getRoles(header));
		}

		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
	}

	protected boolean requiresAutentication(String header) {
		if (header == null || !header.startsWith(JWTService.TOKEN_PREFIX)) {
			return false;
		}
		return true;
	}

}
