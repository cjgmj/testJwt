package com.cjgmj.testJwt.auth.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

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
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.ExpiredJwtException;

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

		try {
			jwtService.getUsername(header);
		} catch (ExpiredJwtException e) {
			String token = jwtService.create(e.getClaims().getSubject(), e.getClaims().get("authorities"));
			response.addHeader(JWTService.HEADER_STRING, JWTService.TOKEN_PREFIX.concat(token));

			Map<String, Object> body = new HashMap<String, Object>();
			body.put("token", token);
			body.put("user", e.getClaims().getSubject());
			body.put("mensaje", "Token renovado con éxito");

			response.getWriter().write(new ObjectMapper().writeValueAsString(body));
			response.setStatus(200);
			response.setContentType("application/json");

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
