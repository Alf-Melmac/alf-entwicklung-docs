---
layout: editorial
---

# Building React SPA with Spring Boot backend and OAuth2 authentication

## What we'll be doing

By the end of this article, you'll have created a single-page, statically served application using React. For authentication and database access, a Spring Boot application is deployed while authenticating to an OAuth2 provider. The content is served through an nginx reverse proxy.

### Tech Stack

Backend: Spring Boot, Spring Security, Lombok

Frontend: React, react-router-dom, axios, @tanstack/react-query



## OAuth2 Configuration

A great place to start is the official spring guide: [https://spring.io/guides/tutorials/spring-boot-oauth2](https://spring.io/guides/tutorials/spring-boot-oauth2)

A brief description of the setup. We're using Discord as a placeholder for the OAuth provider, which could be Discord, Microsoft, GitHub, or any other provider you'd like to connect to.

{% code title="application.properties" %}
```properties
spring.security.oauth2.client.registration.discord.client-id=redacted
spring.security.oauth2.client.registration.discord.client-secret=redacted
spring.security.oauth2.client.registration.discord.authorization-grant-type=authorization_code
spring.security.oauth2.client.registration.discord.scope=identify
spring.security.oauth2.client.registration.discord.redirect-uri={baseUrl}/{action}/oauth2/code/{registrationId}
spring.security.oauth2.client.registration.discord.client-name=redacted
spring.security.oauth2.client.provider.discord.authorization-uri=https://discord.com/oauth2/authorize?prompt=none
spring.security.oauth2.client.provider.discord.token-uri=https://discord.com/api/oauth2/token
spring.security.oauth2.client.provider.discord.user-info-uri=https://discord.com/api/users/@me
spring.security.oauth2.client.provider.discord.user-name-attribute=username
```
{% endcode %}

To map OAuth users to local users, create a user entity. In this example, we're using the Discord snowflakes as unique identifiers. Therefore, we are not using the @GeneratedValue annotation to generate them.

{% code title="User.java" %}
```java
@Entity
@Table(name = "discord_user", uniqueConstraints = {@UniqueConstraint(columnNames = {"id"})})
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class User {
	@Id
	@Column(name = "id", nullable = false, unique = true, updatable = false)
	protected long id;
}
```
{% endcode %}

{% hint style="warning" %}
If you're using Postgres as your database, don't try to name your table `user`. This is a reserved keyword.
{% endhint %}



{% code title="OAuth2EndpointConfig.java" lineNumbers="true" fullWidth="true" %}
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2EndpointConfig {
	private final GuildUsersService guildUsersService;
	private final UserService userService;

	@Bean
	SecurityFilterChain oAuthUserFilterChain(HttpSecurity http) throws Exception {
		http
			.logout(logout -> logout
				.logoutSuccessUrl("/startpage")
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
				.addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(COOKIES)))
			)

			.oauth2Login(login -> login
				.loginPage("/oauth2/authorization/discord")
				.defaultSuccessUrl("/startpage")
				.tokenEndpoint(tokenEndpoint -> tokenEndpoint
						.accessTokenResponseClient(accessTokenResponseClient())
				)
				.userInfoEndpoint(userInfo -> userInfo
						.userService(oAuthUserService())
				)
			);
		return http.build();
	}

	@Bean
	CookieSameSiteSupplier sameSiteSupplier() {
		// Force JSESSIONID cookie to be SameSite=Lax
		return CookieSameSiteSupplier.ofLax();
	}

	@Bean
	OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
		DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();

		client.setRequestEntityConverter(new OAuth2AuthorizationCodeGrantRequestEntityConverter() {
			@Override
			public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest oauth2Request) {
				return withUserAgent(Objects.requireNonNull(super.convert(oauth2Request)));
			}
		});

		return client;
	}

	@Bean
	OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuthUserService() {
		DefaultOAuth2UserService service = new CustomOAuth2UserService(guildUsersService, userService);

		service.setRequestEntityConverter(new OAuth2UserRequestEntityConverter() {
			@Override
			public RequestEntity<?> convert(OAuth2UserRequest userRequest) {
				return withUserAgent(Objects.requireNonNull(super.convert(userRequest)));
			}
		});

		return service;
	}

	private static final String DISCORD_BOT_USER_AGENT = "Discord-OAuth";

	private static RequestEntity<?> withUserAgent(RequestEntity<?> request) {
		HttpHeaders headers = new HttpHeaders();
		headers.putAll(request.getHeaders());
		headers.add(HttpHeaders.USER_AGENT, DISCORD_BOT_USER_AGENT);

		return new RequestEntity<>(request.getBody(), headers, request.getMethod(), request.getUrl());
	}
}
```
{% endcode %}

1. L11: Configure the logout process.
   1. L12: Where to redirect after successful logout.
   2. L13: The endpoint that triggers the logout.
   3. L14: When the user logs out, instruct the browser to delete any cookies sent by the site ([https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data)). In our case this is the `XSRF-TOKEN` and if you're using Tomcat for example, this is the `JSESSIONID`.
2. L17: Configure the login process.
   1. L18: Specify the URL to send users to when login is required.
   2. L19: As with logout, the user will be redirected to this endpoint upon successful login.
3. L20: Discord requires a `Discord-OAuth` `User-Agent` header at the token and user info endpoints. Configure in accordance with the OAuth provider (see `#withUserAgent`).
4. L23: This is where the OAuth user request is consumed. This step creates the `OAuth2User` from the data returned by the provider after login. For example, creating the user if it doesn't already exist in the database and granting authorities. To make things easier, I've excluded the `CustomOauth2UserService` here. You may reference the original [here](https://github.com/Alf-Melmac/slotbotServer/blob/develop/src/main/java/de/webalf/slotbot/configuration/authentication/website/CustomOAuth2UserService.java).

### CORS

<pre class="language-java" data-title="OAuth2EndpointConfig.java"><code class="lang-java">@Bean
SecurityFilterChain oAuthUserFilterChain(HttpSecurity http) throws Exception {
	[...]
	http.
<strong>		.cors(withDefaults())
</strong>	[...]
}
</code></pre>

Apply the default Spring CORS filter.

{% code title="WebMvcConfig.java" %}
```java
@Configuration
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {
	@Value("${server.cors.allowed-origins}")
	private String[] allowedOrigins;

	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**")
			.allowedMethods(GET.name(), POST.name(), PUT.name(), DELETE.name())
			.allowedOrigins(allowedOrigins)
			.allowCredentials(true);
	}
}
```
{% endcode %}

{% hint style="danger" %}
I'm not sure if this is really required. Looking at my production setup, I forgot to configure this, but things still work. Maybe only in dev setup, need to check again.
{% endhint %}

### Recommended optionals

<details>

<summary>CSRF protection</summary>

<pre class="language-java" data-title="OAuth2EndpointConfig.java" data-line-numbers><code class="lang-java">private final AuthenticationSuccessHandler authenticationSuccessHandler;

@Bean
SecurityFilterChain oAuthUserFilterChain(HttpSecurity http) throws Exception {
	// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_angularjs_or_another_javascript_framework
	final CookieCsrfTokenRepository tokenRepository = new CookieCsrfTokenRepository();
	tokenRepository.setCookieCustomizer(cookie -> cookie
		.path("/")
		.httpOnly(false)
		.secure(true)
		.sameSite(STRICT.attributeValue())
	);
	final XorCsrfTokenRequestAttributeHandler delegate = new XorCsrfTokenRequestAttributeHandler();
	// set the name of the attribute the CsrfToken will be populated on
	delegate.setCsrfRequestAttributeName("_csrf");
	// Use only the handle() method of XorCsrfTokenRequestAttributeHandler and the
	// default implementation of resolveCsrfTokenValue() from CsrfTokenRequestHandler
	final CsrfTokenRequestHandler requestHandler = delegate::handle;

	http.
<strong>		.csrf(csrf -> csrf
</strong><strong>			.csrfTokenRepository(tokenRepository)
</strong><strong>			.csrfTokenRequestHandler(requestHandler))
</strong>
		.oauth2Login(login -> login
<strong>			.successHandler(authenticationSuccessHandler)
</strong>			[...]
		)
	[...]
}
</code></pre>

L9: Make the CSRF token available to Javascript. We'll need this later to authenticate our fetches from the frontend.

{% code title="AuthenticationSuccessHandler.java" %}
```java
@Component
public class AuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
		// https://github.com/spring-projects/spring-security/issues/12094#issuecomment-1294150717
		CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		csrfToken.getToken();

		super.onAuthenticationSuccess(request, response, authentication);
	}
}
```
{% endcode %}

</details>

<details>

<summary>Configure a maximum session count</summary>

<pre class="language-java" data-title="OAuth2EndpointConfig.java"><code class="lang-java"><strong>private final SessionRegistry sessionRegistry;
</strong>
@Bean
SecurityFilterChain oAuthUserFilterChain(HttpSecurity http) throws Exception {
	[...]
	http.
<strong>		.sessionManagement(session -> session
</strong><strong>			.maximumSessions(2).sessionRegistry(sessionRegistry)
</strong>		)
	[...]
}
</code></pre>



{% code title="SessionRegistrator.java" %}
```java
@Component
public class SessionRegistrator {
	@Bean
	SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	/**
	 * Needed for session registry to work
	 *
	 * @see SessionRegistryImpl
	 */
	@Bean
	HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}
}
```
{% endcode %}

</details>

## Starting the login process

While Spring already provides a [default login page](https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html#oauth2login-advanced-login-page), we support the user with some nice to have features. To force a session to be created, we create an endpoint that requires authentication. We'll use the `@PreAuthorize` method to do this. Remember to add `@EnableMethodSecurity` to your Spring Boot Application class to enable its use.

```java
@Controller
@RequiredArgsConstructor
@RequestMapping("/login")
public class LoginWebController {
	private final RedirectService redirectService;

	@GetMapping
	@PreAuthorize(HAS_ROLE_EVERYONE)
	public RedirectView login(@RequestParam String redirectUrl) {
		return new RedirectView(redirectService.redirectTo(redirectUrl));
	}
}
```

We create the endpoint in a way that allows us to redirect to any page after the OAuth flow is complete. Since we are leaving our frontend while redirecting to the external provider, we need a way to get back to the page the user had opened. This is particularly useful if there is a login button in a header and we don't want the user to always restart their journey at the defaultSuccessUrl.

```java
public interface RedirectService {
	/**
	 * Creates an absolute path for redirection to the frontend. To do this, the servlet context path is removed
	 *
	 * @param redirectPath relative path
	 */
	String redirectTo(String redirectPath);
}
```

```java
@Service
@Profile("!dev")
public class RedirectServiceImpl implements RedirectService {
	@Value("#{servletContext.contextPath}")
	private String servletContextPath;

	@Override
	public String redirectTo(String redirectPath) {
		return ServletUriComponentsBuilder.fromCurrentContextPath().toUriString()
				.replace(servletContextPath, "")
				+ redirectPath;
	}
}
```

To avoid an [Open Redirect vulnerability](https://learn.snyk.io/lesson/open-redirect/), we'll build the URL from the current request. We remove the servletContextPath (`/backend` if you're following the setup we'll add later) and append the passed redirectPath. This may have been tampered with, but as it's only on the same domain, we're mostly safe.

```java
@Service
@Profile("dev")
public class RedirectServiceDevImpl implements RedirectService {
	@Value("#{servletContext.contextPath}")
	private String servletContextPath;

	@Override
	public String redirectTo(String redirectPath) {
		return ServletUriComponentsBuilder.fromCurrentContextPath().port(3000).toUriString()
				.replace(servletContextPath, "")
				+ redirectPath;
	}
}
```

The only difference for dev mode is the addition of the frontend port, since we won't be serving it locally from the same domain and port combination.

## From Spring View to SPA

But how do we get back to our spa when the defaultSuccessUrl or logoutSuccessUrl is opened? Now let's create the controller to do this.

```java
@Controller
@RequiredArgsConstructor
public class RedirectController {
	private final RedirectService redirectService;

	@GetMapping("/startpage") //OAuth2EndpointConfig logoutSuccessUrl
	public RedirectView redirectToStartpage() {
		return new RedirectView(redirectService.redirectTo("/startpage"));
	}
}
```

We'll use the same redirect logic we built for the login endpoint to redirect to a specific frontend URL. This doesn't have to be the same path, or your redirectService may use some special mapping logic to get the spa routes.



## Frontend Routing

The entry point to our single page application is the router. This is where we specify which urls will display which components in the browser. It will include the route we specified in the RedirectController.

```tsx
const routes: RoutesObject[] = [
    {
        path: '/',
        element: <span>Hello World!</span>,
    },
    {
        path: '/startpage',
        element: <span>Start page</span>,
    }
];

export function App(): JSX.Element {
    const router = createBrowserRouter(routes);

    return (
        <RouterProvider router={router}/> 
    );
}
```

{% hint style="info" %}
[https://reactrouter.com/en/6.25.1/routers/create-browser-router](https://reactrouter.com/en/6.25.1/routers/create-browser-router)
{% endhint %}

<details>

<summary>Outlet</summary>

I won't describe how to use it here, but you might want to take a look at [react routers outlet](https://reactrouter.com/en/main/components/outlet). This component allows you to keep part of the page as you navigate, without having to re-render everything. Especially useful for headers and footers.

Usage example: [Router](https://github.com/Alf-Melmac/slotbot-frontend/blob/develop/src/Router.tsx) & [Outlet](https://github.com/Alf-Melmac/slotbot-frontend/blob/develop/src/features/StandardPage.tsx)

</details>

## API Resolver

To access the backend API through the user's browser, we need a similar URL resolver to the RedirectService.

```typescript
export function getBackendUrl(): string {
	let hostname = window.location.hostname;
	if (import.meta.env.DEV) {
		hostname = `${hostname}:8080`;
	}
	return `${window.location.protocol}//${hostname}/backend`;
}

```

This directly matches our spring application's additional configuration. Again, in dev mode, we need to set the port.

{% code title="application.properties" %}
```properties
server.port=8080
server.servlet.context-path=/backend
```
{% endcode %}

To make things easier, we'll use this backend API URL directly as the base URL for every axios request.

```typescript
const backendClient = axios.create({
	baseURL: getBackendUrl(),
	withCredentials: import.meta.env.DEV ? true : undefined,
	withXSRFToken: import.meta.env.DEV ? true : undefined,
});
```

While the Cookies are automatically added to the requests if we're on the same domain-port-pair, you already know it, in dev mode we force axios to send it in every request. This only works if the `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` headers are sent (Reference `WebMvcConfig.java`).

## Login and Logout

```typescript
window.location.href = `${getBackendUrl()}/login?redirectUrl=${window.location.pathname}`;

window.location.href = `${getBackendUrl()}/logout
```

That's it! Bind them to any click listener on a button you want, and the backend will automatically set all the necessary cookies and axios will pick them up.

<details>

<summary>In a context</summary>

You may want to access the logged-in user in multiple places, or provide multiple login/logout buttons. That's where an auth context can help.

```tsx
export function AuthProvider(props: Readonly<PropsWithChildren>): JSX.Element {
	const [user, setUser] = useState<AuthContextType['user']>();

	const {user: authenticatedUser} = authenticationQuery();

	useEffect(() => {
			setUser(authenticatedUser);
		}, [authenticatedUser],
	);

	const login = () => {
		window.location.href = `${getBackendUrl()}/login?redirectUrl=${window.location.pathname}`;
	};

	const logout = () => {
		window.location.href = `${getBackendUrl()}/logout`;
	};

	const value = useMemo((): AuthContextType => ({user, login, logout}), [user, login, logout]);
	return <AuthContext.Provider value={value}>{props.children}</AuthContext.Provider>;
}

interface DiscordUserDto {
	id: string;
	name: string;
	avatarUrl: string;
}

interface AuthContextType {
	user?: DiscordUserDto;
	login: () => void;
	logout: () => void;
}

const AuthContext = createContext<AuthContextType>(null!);

export function useAuth() {
	return useContext(AuthContext);
}
```

Wrap the Router with the AuthProvider and start using it.

</details>

## Using the session

### Who is logged in

```java
@RestController
@RequestMapping("/authentication")
public class AuthenticationController {
	@GetMapping
	public DiscordUserDto getAuthenticatedUser(@AuthenticationPrincipal OAuth2User oAuth2User) {
		return DiscordUserAssembler.toDto(oAuth2User);
	}
}
```

With the `@AuthenticationPrincipal` we can inject the currently active user principal. With this representation, we can provide information that should be publicly available on the front end. The attribute names are not standardised and will vary between different providers. (This is the endpoint that is used for the Login and Logout context)

In static methods, you can access the security context to get the currently logged in user:

```java
final Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
if (principal instanceof OAuth2User oAuth2User) {
	return oAuth2User;
}
```

### Require authentication on a route

```tsx
export function RequireAuth(props: Readonly<{children: ReactNode}>): JSX.Element {
	const {children} = props;

	const {user, login} = useAuth();

	if (user === undefined) return <></>;

	return <>
		{user ?
			children
			:
			<OnMount do={login}/>
		}
	</>;
}

type RedirectProps = {
	do: () => void;
};

function OnMount(props: Readonly<RedirectProps>): JSX.Element {
	useEffect(() => {
		props.do();
	}, []);

	return <></>;
}
```



## Nginx setup

{% hint style="info" %}
For security reasons this is obviously not complete. Feel free to contact me if you need more information.
{% endhint %}

```apacheconf
server {
    root /frontend-project/dist;
    
    location / {
        try_files $uri /index.html;
    }

    location /backend {
      proxy_pass http://127.0.0.1:8443;
      proxy_set_header Host $http_host;
      proxy_redirect http:// https://;
      proxy_http_version 1.1;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
    }
}
```

This will serve the frontend at `example.com` and the backend at `example.com/backend`, just like we configured in the servlet context path.



## Summary

We've created a Spring Boot backend that handles authentication with an OAuth2 provider. For login and logout, the user is redirected to the Spring Boot application. The session is maintained by the server-side backend and sends all the necessary information to the client browser, just as you would with any database information.

### Login-Flow

1. Browsing the page at `example.de` and clicking on login
2. `example.de/backend/login` (which requires authorization and therefore redirects)
3. `example.de/backend/oauth2/authorization/discord` (starts the authorization process)
4. `discord.com/oauth2/authorize`
5. `example.de/backend/login/oauth2/code/discord` (callback with oauth code)
6. `example.de/backend/login` (back to the starting point)

### Logout-Flow

1. Browsing the page at `example.de` and clicking on logout
2. `example.de/backend/logout` (Does the Front-Channel logout)
3. Redirect to the logoutSuccessUrl
