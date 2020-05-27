package rc.bootsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.inMemoryAuthentication()
			.withUser("admin").password(passwordEncoder().encode("admin123"))
			.roles("ADMIN")
			.authorities("ACCESS_TEST1" , "ACCESS_TEST2")
			.and()
			.withUser("user").password(passwordEncoder().encode("user"))
			.roles("USER")
			.and()
			.withUser("manager").password(passwordEncoder().encode("manager"))
			.roles("MANAGER")
			.authorities("ACCESS_TEST1");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//Here is what happening here: 
		//previously there is only one authorization which was anyRequest().authorize()
		//but now even authorized user will be given access based on their role.
		///profile/index : means access to profile/index url
		//profile/** means any route matches profile then anything.
		http
			.authorizeRequests()
			.antMatchers("/index.html").permitAll() //home page accessed by everyone
			.antMatchers("/profile/**").authenticated() //any authenticated user can access profile page
            .antMatchers("/admin/**").hasRole("ADMIN") //only admin can access the admin routes
            .antMatchers("/management/**").hasAnyRole("ADMIN" , "MANAGER") //only admin and management role can access management pages
            .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
            .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
			.and()
			.httpBasic();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
}
