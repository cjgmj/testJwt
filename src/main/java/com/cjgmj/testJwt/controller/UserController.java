package com.cjgmj.testJwt.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cjgmj.testJwt.auth.service.JWTService;
import com.cjgmj.testJwt.auth.service.LogoutService;
import com.cjgmj.testJwt.model.RoleEntity;
import com.cjgmj.testJwt.model.UserEntity;

import io.jsonwebtoken.Claims;

@RestController
@RequestMapping("/user")
public class UserController {

	@Autowired
	private JWTService jwtService;

	@Autowired
	private LogoutService manageJWTService;

	@GetMapping("/")
	@Secured("ROLE_ADMIN")
	public UserEntity getUser(HttpServletRequest request) {
		String header = request.getHeader(JWTService.HEADER_STRING);
		Claims claims = null;

		if (jwtService.validate(header)) {
			claims = jwtService.getClaims(header);
			return new UserEntity(claims.get("name").toString(), claims.get("surname").toString(), claims.getSubject(),
					getRoles(header));
		}

		return null;
	}

	@PostMapping("/logout")
	public void logout(HttpServletRequest request) {
		String header = request.getHeader(JWTService.HEADER_STRING);
		manageJWTService.logout(jwtService.resolve(header));
	}

	private List<RoleEntity> getRoles(String token) {
		List<RoleEntity> roles = new ArrayList<>();
		Collection<? extends GrantedAuthority> authorities;
		try {
			authorities = jwtService.getRoles(token);

			Iterator<? extends GrantedAuthority> iterator = authorities.iterator();

			while (iterator.hasNext()) {
				roles.add(new RoleEntity(iterator.next().getAuthority().toString()));
			}

			return roles;
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

}
