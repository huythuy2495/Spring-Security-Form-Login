# Spring-Security-Form-Login
1. Introduction

This article is going to focus on Login with Spring Security. We’re going to build on top of the simple previous Spring MVC example, as that’s a necessary part of setting up the web application along with the login mechanism.

2. The Maven Dependencies

To add Maven dependencies to the project, please see the Spring Security with Maven article. Both standard spring-security-web and spring-security-config will be required.

3. The web.xml

The Spring Security configuration in the web.xml is simple – only an additional filter added to the standard Spring MVC web.xml:



<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee 
  http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
  version="3.1">
 
    <display-name>Spring Secured Application</display-name>
 
    <!-- Spring MVC -->
    <servlet>
        <servlet-name>mvc</servlet-name>
        <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
        <load-on-startup>1</load-on-startup>
    </servlet>
    <servlet-mapping>
        <servlet-name>mvc</servlet-name>
        <url-pattern>/</url-pattern>
    </servlet-mapping>
 
    <context-param>
        <param-name>contextClass</param-name>
        <param-value>
          org.springframework.web.context.support.AnnotationConfigWebApplicationContext
        </param-value>
    </context-param>
    <context-param>
        <param-name>contextConfigLocation</param-name>
        <param-value>org.baeldung.spring.web.config</param-value>
    </context-param>
    <listener>
        <listener-class>
          org.springframework.web.context.ContextLoaderListener
        </listener-class>
    </listener>
 
    <!-- Spring Security -->
    <filter>
        <filter-name>springSecurityFilterChain</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>springSecurityFilterChain</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>
The filter – DelegatingFilterProxy – simply delegates to a Spring-managed bean – the FilterChainProxy – which itself is able to benefit from full Spring bean lifecycle management and such.

4. The Spring Security XML Configuration

The Spring configuration is mostly written in Java, but Spring Security configuration doesn’t yet support full Java and still needs to be XML for the most part. There is an ongoing effort to add Java-based configuration for Spring Security, but this is not yet mature.

The overall project is using Java configuration, so the XML configuration file needs to be imported via a Java @Configuration class:



@Configuration
@ImportResource({ "classpath:webSecurityConfig.xml" })
public class SecSecurityConfig {
   public SecSecurityConfig() {
      super();
   }
}
The Spring Security XML Configuration – webSecurityConfig.xml:


<?xml version="1.0" encoding="UTF-8"?>
<beans:beans xmlns="http://www.springframework.org/schema/security"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:beans="http://www.springframework.org/schema/beans"
  xsi:schemaLocation="
    http://www.springframework.org/schema/security 
    http://www.springframework.org/schema/security/spring-security-4.0.xsd
    http://www.springframework.org/schema/beans 
    http://www.springframework.org/schema/beans/spring-beans-4.2.xsd">
 
   <http use-expressions="true">
      <intercept-url pattern="/login*" access="isAnonymous()" />
      <intercept-url pattern="/**" access="isAuthenticated()"/>
 
      <form-login
         login-page='/login.html'
         default-target-url="/homepage.html"
         authentication-failure-url="/login.html?error=true" />
 
      <logout logout-success-url="/login.html" />
 
   </http>
   <authentication-manager>
      <authentication-provider>
         <user-service>
            <user name="user1" password="user1Pass" authorities="ROLE_USER" />
         </user-service>
      </authentication-provider>
   </authentication-manager>
</beans:beans>
4.1. <intercept-url>

We are allowing anonymous access on /login so that users can authenticate. We are also securing everything else.

Note that the order of the <intercept-url> element is significant – the more specific rules need to come first, followed by the more general ones.

4.2. <form-login>

login-page – the custom login page
default-target-url – the landing page after a successful login
authentication-failure-url – the landing page after an unsuccessful login
4.3. <authentication-manager>

The Authentication Provider is backed by a simple, in-memory implementation – InMemoryUserDetailsManager specifically – configured in plain text. This only exists in Spring 3.1 and above and is meant to be used for rapid prototyping when a full persistence mechanism is not yet necessary.

5. The Security Java Configuration

Here’s the corresponding Java configuration:


@Configuration
@EnableWebSecurity
public class SecSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
          .withUser("user1").password("user1Pass").roles("USER");
    }
 
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
          .authorizeRequests()
          .antMatchers("/login*").anonymous()
          .anyRequest().authenticated()
          .and()
          .formLogin()
          .loginPage("/login.html")
          .defaultSuccessUrl("/homepage.html")
          .failureUrl("/login.html?error=true")
          .and()
          .logout().logoutSuccessUrl("/login.html");
    }
}
6. The Login Form

The login form page is going to be registered with Spring MVC using the straightforward mechanism to map views names to URLs with no need for an explicit controller in between:

1
registry.addViewController("/login.html");
This, of course, corresponds to the login.jsp:


<html>
<head></head>
<body>
   <h1>Login</h1>
   <form name='f' action="login" method='POST'>
      <table>
         <tr>
            <td>User:</td>
            <td><input type='text' name='username' value=''></td>
         </tr>
         <tr>
            <td>Password:</td>
            <td><input type='password' name='password' /></td>
         </tr>
         <tr>
            <td><input name="submit" type="submit" value="submit" /></td>
         </tr>
      </table>
  </form>
</body>
</html>
The Spring Login form has the following relevant artifacts:

login – the URL where the form is POSTed to trigger the authentication process
username – the username
password – the password
7. Further Configuring Spring Login

We briefly discussed a few configurations of the login mechanism when we introduced the Spring Security XML Configuration above – let’s go into some detail now.

One reason to override most of the defaults in Spring Security is to hide the fact that the application is secured with Spring Security and minimize the information a potential attacker knows about the application.

Fully configured, the <form-login> element looks like this:

1
2
3
4
5
6
<form-login
  login-page='/login.html'
  login-processing-url="/perform_login"
  default-target-url="/homepage.html"
  authentication-failure-url="/login.html?error=true"
  always-use-default-target="true"/>
Or, via Java configuration:

1
2
3
4
5
6
7
8
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
      .loginPage("/login.html")
      .loginProcessingUrl("/perform_login")
      .defaultSuccessUrl("/homepage.html",true)
      .failureUrl("/login.html?error=true")
}
7.1. The Login Page

The custom login page is configured via the login-page attribute on <form-login>:

1
login-page='/login.html'
Or, via Java configuration:

1
2
http.formLogin()
  .loginPage("/login.html")
If this is not specified, a default URL is used – spring_security_login – and Spring Security will generate a very basic Login Form at that URL.

7.2. The POST URL for Login

The default URL where the Spring Login will POST to trigger the authentication process is /login which used to be /j_spring_security_check before Spring Security 4.

This URL can be overridden via the login-processing-url attribute on <form-login>:

1
login-processing-url="/perform_login"
Or, via Java configuration:

1
2
http.formLogin()
  .loginProcessingUrl("/perform_login")
A good reason to override this default URL is to hide the fact that the application is actually secured with Spring Security – that information should not be available externally.

7.3. The Landing Page on Success

After a successful Login process, the user is redirected to a page – which by default is the root of the web application.

This can be overridden via the default-target-url attribute on <form-login>:

1
default-target-url="/homepage.html"
Or, via Java configuration:

1
2
http.formLogin()
  .defaultSuccessUrl("/homepage.html")
In case the always-use-default-target is set to true, then the user is always redirected to this page. If that attribute is set to false, then the user will be redirected to the previous page they wanted to visit before being promoted to authenticate.

7.4. The Landing Page on Failure

Same as with the Login Page, the Login Failure Page is autogenerated by Spring Security at /login?error by default.

This can be overridden via the authentication-failure-url attribute on <form-login>:

1
authentication-failure-url="/login.html?error=true"
Or, via Java configuration:

1
2
http.formLogin()
  .failureUrl("/login.html?error=true")
8. Conclusion

In this Spring Login Example, we configured a simple authentication process – we discussed the Spring Security Login Form, the Security XML Configuration and some of the more advanced customizations available in the namespace.

The implementation of this Spring Login tutorial can be found in the GitHub project – this is an Eclipse based project, so it should be easy to import and run as it is.

When the project runs locally, the sample HTML can be accessed at:

1
http://localhost:8080/spring-security-login/login.html
