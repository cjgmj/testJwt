package com.cjgmj.testJwt.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.cjgmj.testJwt.model.Role;
import com.cjgmj.testJwt.repository.UserRepository;

@Service
public class JpaUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepository userRepository;

	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<com.cjgmj.testJwt.model.User> user = userRepository.findByUsername(username);

		if (user.isPresent()) {
			List<GrantedAuthority> authorities = new ArrayList<>();

			for (Role role : user.get().getRoles()) {
				authorities.add(new SimpleGrantedAuthority(role.getAuthority()));
			}

			if(authorities.isEmpty()) {
				throw new UsernameNotFoundException("El usuario no tiene roles asignados");
			}
			
			return new User(user.get().getUsername(), user.get().getPassword(), user.get().getEnabled(), true,
					true, true, authorities);
		}

		throw new UsernameNotFoundException("El usuario no existe");
	}

}
