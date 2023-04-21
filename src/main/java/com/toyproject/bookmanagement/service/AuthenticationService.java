package com.toyproject.bookmanagement.service;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.toyproject.bookmanagement.dto.auth.JwtRespDto;
import com.toyproject.bookmanagement.dto.auth.LoginReqDto;
import com.toyproject.bookmanagement.dto.auth.SignupReqDto;
import com.toyproject.bookmanagement.entity.Authority;
import com.toyproject.bookmanagement.entity.User;
import com.toyproject.bookmanagement.exception.CustomException;
import com.toyproject.bookmanagement.exception.ErrorMap;
import com.toyproject.bookmanagement.repository.UserRepository;
import com.toyproject.bookmanagement.security.jwt.JwtTokenProvider;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class AuthenticationService implements UserDetailsService {
	
	private final UserRepository userRepository;
	private final AuthenticationManagerBuilder authenticationManagerBuilder;
	private final JwtTokenProvider jwtTokenProvider;
	

	public void checkDuplicatedEmail(String email) { // 이메일 중복 확인
		if(userRepository.findUserByEmail(email) != null) {
			throw new CustomException("DuplicatedEmail 오류", ErrorMap.builder().put("email", "사용중").build());
		}
	}
	
	public void signup(SignupReqDto signupReqDto) { //회원가입 권한
		User userEntity = signupReqDto.toEntity();
		userRepository.saveUser(userEntity);
		
		userRepository.saveAuthority(Authority.builder().userId(userEntity.getUserId()).roleId(1).build());
	}
	
	public JwtRespDto signin(LoginReqDto loginReqDto) {
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = 
				new UsernamePasswordAuthenticationToken(loginReqDto.getEmail(),loginReqDto.getPassword()); //요청보낼 id password를 매니저가 알아볼수있게 변환
	
		Authentication authentication = authenticationManagerBuilder.getObject().authenticate(usernamePasswordAuthenticationToken);
		
		return jwtTokenProvider.createToken(authentication);
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		User userEntity = userRepository.findUserByEmail(username);
		
		if(userEntity == null) {
			throw new CustomException("로그인 실패", ErrorMap.builder().put("email", "사용자 정보를 확인하세요").build());
		}
		
		return userEntity.toPrincipal();
	}
	
	public boolean authenticated(String accessToken) {
		return jwtTokenProvider.validateToken(jwtTokenProvider.getToken(accessToken));
	}
 
	
}