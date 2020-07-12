package com.zpark.security.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        super.configure(http);

        //定制请求的授权规则
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");
        //开启配置的登录功能，如果没有登录，没有权限就会来到登录页面
//        http.formLogin();//security自动生成登录的页面
        //来到自己的登录页
//        http.formLogin().loginPage("/userlogin");//告诉secutiy我们的security登录法什么请求
        http.formLogin()
                .usernameParameter("user")
                .passwordParameter("pwd")
                .loginPage("/userlogin");


        //1 login来到登录页
        // 2重定向到/login?error表示登录失败
        //3更多详细规定
        //4  默认post形式的/login代表处理登录
        //5 一旦定制定制loginPage，那么loginPage的post请求就是登录


        //开启自动配置的注销功能
        http.logout().logoutSuccessUrl("/");//注销成功来到首页
     // http.logout();
        //1 访问loginout表示用户注销清空session
        //2 注销成功·会返回/login?logout页面

        //开启记住我功能
        http.rememberMe();
        //自定义remember me的参数名字
        http.rememberMe().rememberMeParameter("remember");
        //登录成功以后，将cookie发给浏览器，以后访问页面带上这个cookie
        //只要通过检查就可以免登录
        //点击注销会删除cookie



    }
//定义认证规则
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       // super.configure(auth);
        auth.inMemoryAuthentication().withUser("zhangsan").password("123").roles("VIP1","VIP2")
                .and()
                .withUser("lisi").password("123").roles("VIP2","VIP3")
                .and()
                .withUser("wangwu").password("123").roles("VIP1","VIP3");
    }
}
