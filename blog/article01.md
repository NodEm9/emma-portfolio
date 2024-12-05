<div style="width: 100%; background: black; padding: 10px; padding-left: 15px; top: 0; position: relative;" ><a href="../blog.html" style="color: white;">< Back</a></div>

# Industry Standard Tools/Libraries/Ways to Add Authorization and Authentication To Modern Application

<div class="article-header" >
<img src="../media/heroImage.png" alt="" width="40" style="margin-right: 10px; border-radius: 25px;"/> <b>Author:</b> Emmanuel</div>  

**Date:**  2024-12-05
<br>

At the bottom of this article, you will find recommendations and implementation basics, what is the authorization and authentication approach to choose in each scenario, and why. We will also look at the pros and cons of various authorization and authentication types and how to make decisions that's best for your application.

<br>

## <h2 style="text-decoration: underline"> Table of Contents:
</h2>

* Adding Authentication
* Authorization 
* Industry-Standard Tools and Libraries
* Full-Service Authentication and Authorization Providers
* Middleware for Protection
* Best Practices
* Example Workflow
* Comparison of session-based authentication and stateless authentication (e.g., JWT), along with recommendations for security-conscious use cases.

The issue of security in the web/cyber security is an enormous and broad topic, I will be going straight to the points I consider useful at all levels.

Adding authentication and authorization for example, to a REST API with user and product inventory routes is crucial for security. The choice of tools and libraries depends on your stack and requirements. But here are industry-standard ways to implement these features:

#### Authentication:

What is authentication: <p style="background: green; color: yellow; padding: 15px">Authentication refers to a process or situation where a server needs to know or verify who is accessing its content. Authentication would usually go both ways the client also wants to be sure the server provider is really who they say they are, so while the server is trying to verify that the client is who they say they are so does a legitimate client the server. In a single sentence, Authentication verifies the identity of a user.</p>

**Industry-Standard Tools and Libraries**

1.**JWT (JSON Web Tokens):**

* <span style="font-size: 14px; font-weight: bold">Library:</span>
  * [jsonwebtoken](https://jwt.io/introduction) (Node.js)
*  <span style="font-size: 14px; font-weight: bold">Use Case:</span> Stateless authentication, where the server does not store session data.
*  <p style="font-size: 14px; font-weight: bold">How It Works:</p>

    * On login, a ``token`` is generated and signed with a ``secret or private key``.
    * The ``token`` is sent to the ``client`` and included in every request (usually in the Authorization header as Bearer ``token`` ).
    * The server ``verifies the token to authenticate the user``.
<br />

 <p style="font-size: 14px; font-weight: bold">Basic Example</p>

```ts
* TypeScript:

import jwt from 'jsonwebtoken';

const generateToken = (userId: string) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET!, { expiresIn: '1h' });
};

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Forbidden' });
  }
};
```

2.**OAuth2:**

* <span style="font-size: 14px; font-weight: bold">Libraries:</span>
  * [Passport.js](https://www.passportjs.org/) (general-purpose, supports multiple strategies).
  * [OAuth2orize](https://github.com/jaredhanson/oauth2orize) (for building an OAuth2 provider).

* <span style="font-size: 14px; font-weight: bold">Use Case:</span>  When integrating with third-party identity providers (e.g., Google, Facebook, GitHub).

*  <p style="font-size: 14px; font-weight: bold">How It Works:</p> Users log in using third-party accounts, and your API validates the access tokens issued by these providers.

3.**Session-Based Authentication:**

* <span style="font-size: 14px; font-weight: bold">Library:</span> 
  * [express-session](https://github.com/expressjs/session)

* <span style="font-size: 14px; font-weight: bold">Use Case:</span>  When you need server-side session storage for user authentication.
* <p style="font-size: 14px; font-weight: bold">How It Works:</p>

  * On login, the server creates a session and stores it in a database.
  * A session cookie is sent to the client for subsequent requests.

  <br>

#### Authorization

<p style="background: green; color: yellow; padding: 15px">On the other hand, authorization simply means controlling access to resources based on user roles and permissions.</p>

**Industry-Standard Tools and Libraries**

1.<span style="font-size: 14px; font-weight: bold">Role-Based Access Control (RBAC):</span>

* <span style="font-size: 14px; font-weight: bold">Libraries:</span>

  * [casl](https://casl.js.org/v6/en/) (highly flexible for defining abilities and roles).
  * [accesscontrol](https://github.com/onury/accesscontrol#readme) (simple RBAC library).

* <p style="font-size: 14px; font-weight: bold">How It Works:</p>

  * Define roles (e.g., ``admin``, ``user``, ``manager``).
  * Associate permissions with routes (e.g., ``admin`` can manage products, ``user`` can view inventory).
  * Middleware checks user roles/permissions before allowing access.
  <br />

 <p style="font-size: 14px; font-weight: bold">Example with CASL:</p>

```ts
* TypeScript:

import { AbilityBuilder, Ability } from '@casl/ability';

const defineAbilitiesFor = (user) => {
  const { can, cannot, build } = new AbilityBuilder(Ability);

  if (user.role === 'admin') {
    can('manage', 'all'); // Admins can do everything
  } else {
    can('read', 'Product'); // Regular users can only read products
    cannot('delete', 'Product'); // Regular users cannot delete products
  }

  return build();
};

const checkPermission = (action, resource) => (req, res, next) => {
  const ability = defineAbilitiesFor(req.user);
  if (ability.can(action, resource)) {
    return next();
  }
  res.status(403).json({ message: 'Forbidden' });
};

// Use in routes
app.delete('/products/:id', checkPermission('delete', 'Product'), (req, res) => {
  // Product deletion logic
});
```
2.**Attribute-Based Access Control (ABAC):**

* <span style="font-size: 14px; font-weight: bold">Libraries:</span>
  * [casbin](https://casbin.org/) (ABAC with flexible policy configurations).

* <span style="font-size: 14px; font-weight: bold">How It Works:</span> Policies define access based on user attributes, resource attributes, and environmental context.

#### Full-Service Authentication and Authorization Providers

For projects where you don’t want to build these systems from scratch, use managed services:

1.**Auth0:**

* Provides full authentication, authorization, and user management.
* Supports passwordless login, social logins, and multi-factor authentication.
* Easy to integrate with Express via [Auth0 SDK](https://auth0.com/docs/libraries).

2 **Firebase Authentication:**

* Part of [Google Firebase](https://firebase.google.com/).
* Handles email/password, social login, and phone authentication.
* Best for projects already using Firebase.

3.**AWS Cognito:** 

* Amazon’s identity and access management service. [AWS Cognito](https://aws.amazon.com/de/cognito/)
* Ideal for applications deployed on AWS.

4.**Okta:**

* Enterprise-grade identity service.
* Great for complex user management needs.

####  Middleware for Protection

In simple terms, Middleware ensures that only authorized users can access protected routes.

 <p style="font-size: 14px; font-weight: bold">Example Middleware for Authentication:</p>

```ts
* TypeScript:

import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

const authenticate = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Forbidden' });
  }
};

export default authenticate;
```

5.**Best Practices**

* <span style="font-size: 14px; font-weight: bold">Use HTTPS:</span>
  * Always secure your API with HTTPS to protect sensitive data.
* <span style="font-size: 14px; font-weight: bold">Secure JWTs:</span>
  * Use strong secrets for signing tokens.
  * Set expiration times for tokens and handle refresh tokens securely.
* <span style="font-size: 14px; font-weight: bold">Rate Limiting:</span>
  * Use libraries like express-rate-limit to prevent abuse.
* <span style="font-size: 14px; font-weight: bold">Validate Input:</span>
  * Use libraries like Joi or Zod to validate incoming requests.
* <span style="font-size: 14px; font-weight: bold">Audit Logs:</span>
  * Maintain logs for authentication and authorization events for monitoring and debugging.

#### Example Workflow

1.**Authentication:**

  * User logs in with email/password.
  * A JWT is issued and sent to the client

2.**Authorization:**

  * Each route checks the user's role/permissions using middleware.
  * Actions like creating products are restricted to admin users.

3.**Protected Routes:**

  * Routes validate the JWT and allow access only if the token is valid.

### <p style="background: purple; color: yellow; padding: 15px">Comparison of session-based authentication and stateless authentication (e.g., JWT), along with recommendations for security-conscious use cases.</p>

#### Session-Based Authentication

Session-based authentication involves storing session data on the server and using cookies to maintain user sessions.

<span style="font-size: 14px; font-weight: bold">How It Works:</span>

  1. User logs in, and the server creates a session (a unique ID linked to the user) and stores it in a database or in-memory store (e.g., Redis).

  2. The session ID is sent to the client as a cookie.

  3. On subsequent requests, the client includes the cookie, and the server retrieves the session data to authenticate the user.

**Pros:**

* <span style="font-size: 14px; font-weight: bold">Server-Side Control:</span>
  * Session data is stored on the server, so the server can invalidate a session at any time (e.g., during logout or for suspicious activity).

* <span style="font-size: 14px; font-weight: bold">Easier to Implement in Monolithic Applications:</span>
  * Especially when the frontend and backend are tightly coupled.

* <span style="font-size: 14px; font-weight: bold">More Secure Against Token Theft</span>
  * Since cookies can be configured with ``HttpOnly``, ``Secure``, and ``SameSite`` attributes, they are less likely to be stolen via client-side attacks like XSS.

**Cons:**

* <span style="font-size: 14px; font-weight: bold">Scalability Issues</span>

  * The server must store session data, which increases memory usage as the number of users grows. Scaling requires a centralized session store (e.g., Redis), which adds complexity.

* <span style="font-size: 14px; font-weight: bold">Tied to Cookies</span>

  * Requires careful configuration of cookies (``HttpOnly``, ``Secure``, ``SameSite``, etc.) to prevent attacks like CSRF and XSS.

* <span style="font-size: 14px; font-weight: bold">Stateful</span>

  * Sessions need to be stored and managed, making it less suitable for highly distributed or serverless architectures.

#### Stateless Authentication (JWT)

Stateless authentication uses self-contained tokens, typically in the form of JSON Web Tokens (JWTs), to authenticate users.

<p style="font-size: 14px; font-weight: bold">How It Works:</p>

 1. User logs in, and the server generates a signed JWT containing claims (e.g., user ID, roles).

 2.  The token is sent to the client (usually stored in ``Authorization`` headers or localStorage).

 3. On subsequent requests, the server validates the token's signature without storing any state.

**Pros:**

* <p style="font-size: 14px; font-weight: bold">Scalability:</p>

  * No need to store session data on the server. Each request is stateless, making it ideal for distributed or serverless environments.

* <p style="font-size: 14px; font-weight: bold">Flexibility:</p>

  * Tokens can be used across multiple services or APIs without needing centralized session storage.

* <p style="font-size: 14px; font-weight: bold">Performance:</p>

  * Eliminates database lookups for session data.

**Cons:**

  * <p style="font-size: 14px; font-weight: bold">Token Revocation</p>

    * Once issued, tokens cannot be easily revoked unless you implement a token blacklist, which reintroduces some state.

* <p style="font-size: 14px; font-weight: bold">Security Concerns with Token Storage</p>

  * Storing tokens in ``localStorage`` exposes them to XSS attacks, while storing them in cookies makes them vulnerable to CSRF attacks (though mitigated with ``SameSite`` cookies).

* <p style="font-size: 14px; font-weight: bold">Payload Size</p>

  * Tokens can grow large if they include too many claims, which increases request sizes.

#### Security Considerations

   **Session-Based Authentication:**

   * <p style="font-size: 14px; font-weight: bold">Pros for Security:</p>

      * Centralized session management allows easy invalidation of compromised sessions.

      * ``HttpOnly`` and ``Secure`` cookies mitigate risks from XSS.
      * Strong against CSRF when combined with proper cookie attributes and CSRF tokens.

   * <p style="font-size: 14px; font-weight: bold">Cons for Security</p>

      * Server needs to trust and properly protect the session store.
      * More configuration is required to secure cookies properly.
  
**Stateless Authentication (JWT):**
  * <p style="font-size: 14px; font-weight: bold">Pros for Security:</p>

      * Tokens are signed, so they cannot be tampered with.
      * Can include expiration times to limit the window for token abuse.
   * <p style="font-size: 14px; font-weight: bold">Cons for Security:</p>

      * Difficult to revoke tokens without additional mechanisms like a blacklist.
      * Tokens stored in the client are vulnerable to theft, requiring secure storage and transport mechanisms.

#### Best Choice for Security

  The best choice depends on your architecture and specific requirements. Here’s a recommendation based on security concerns:

**Use Session-Based Authentication When:**


* You are building a monolithic application with centralized session storage.
* You prioritize security over scalability (e.g., banking apps, internal enterprise systems).
* You want fine-grained control over session invalidation.
  
**Use Stateless Authentication (JWT) When:**

* You are building a distributed or serverless application.
* Scalability and performance are critical.
* You are comfortable implementing additional security measures (e.g., token rotation, blacklisting, shorter token lifetimes).

#### Hybrid Approach (Best Practice for Security and Scalability)

You can combine the strengths of both approaches:

* Use stateless JWTs for initial authentication but issue short-lived tokens.
* Use a refresh token stored in a secure, HttpOnly cookie for reissuing tokens when they expire.
* Implement a token blacklist or a token revocation list to handle compromised tokens.

<p style="font-size: 14px; font-weight: bold">Example:</p>

1. JWT for access: Short-lived token (e.g., 15 minutes) stored in memory or headers.
2. Refresh token: Long-lived, securely stored (e.g., in an HttpOnly cookie).
3. Backend logic

    * Validate access tokens for normal requests.
    * Use refresh tokens only when access tokens expire.
    * Maintain a blacklist of revoked refresh tokens.


### Summary Table

<table>
<tr>
  <th>Feature</th>
  <th>Session-Based Authentication</th>
  <th>Stateless Authentication (JWT)</th>
</tr>

<tr>
  <td style="font-size: 14px; font-weight: bold">Scalability</td>
  <td style="font-size: 14px;">Limited, requires session store</td>
  <td style="font-size: 14px;">Highly scalable</td>
</tr>
<tr>
  <td style="font-size: 14px; font-weight: bold">Ease of Implementation</td>
    <td style="font-size: 14px;">Simpler for monoliths</td>
  <td style="font-size: 14px;">Simpler for distributed systems</td>
</tr>
<tr>
  <td style="font-size: 14px; font-weight: bold">Security</td>
    <td style="font-size: 14px;">Stronger control, revocable</td>
  <td style="font-size: 14px;">Harder to revoke</td>
</tr>
<tr>
<td style="font-size: 14px; font-weight: bold">Storage</td>
  <td style="font-size: 14px;">Server-side</td>
  <td style="font-size: 14px;">Client-side</td>
</tr>
<tr>
<td style="font-size: 14px; font-weight: bold">Use Case</td>
 <td style="font-size: 14px;">Banking, enterprise systems</td>
  <td style="font-size: 14px;">Distributed systems, APIs, microservices</td>
</tr>
</table>

### Conclusion

For security-sensitive use cases, session-based authentication with well-configured cookies is generally safer. For distributed systems, consider a hybrid approach to balance security and scalability.
<br>
<br>

### Recomendation and Example

When combining [Passport.js](https://www.passportjs.org/) with JWT (stateless authentication), the industry-standard strategy is the ``passport-jwt`` strategy. This approach leverages JSON Web Tokens for authentication while benefiting from Passport's modularity and middleware-based integration.

**Why** ``passport-jwt?``

1.**Stateless Authentication:**

   * No need for server-side session management. The server only validates the JWT, which contains all the necessary user information.

2.**Compatibility:**

  * passport-jwt works seamlessly with token-based workflows, such as API authentication or Single Page Applications (SPAs).

3.**Security:**

  * JWTs are signed using a secret (HS256) or private/public key pair (RS256), ensuring tamper-proof authentication tokens.

4.**Flexibility:**

  * Works well with other Passport strategies, allowing a hybrid approach (e.g., OAuth2 for initial login, JWT for subsequent requests)


#### Typical Setup for ``passport-jwt``

1.**Install Required Packages**

```bash
bash
npm install passport passport-jwt jsonwebtoken
```

2.**Configure the JWT Strategy**

```ts
import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';

// Your secret or private key
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

// JWT options
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: JWT_SECRET,
};

// Define the strategy
passport.use(
  new JwtStrategy(opts, async (jwtPayload, done) => {
    try {
      // Example: Validate the user based on the payload
      const user = await findUserById(jwtPayload.id); // Replace with your DB call
      if (user) {
        return done(null, user); // Pass user to req.user
      }
      return done(null, false); // No user found
    } catch (error) {
      return done(error, false);
    }
  })
);
```

3.**Issue a JWT on Login**
Use a library like ``jsonwebtoken`` to generate a token when the user logs in.

```ts
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role }, // Payload
    JWT_SECRET,
    { expiresIn: '1h' } // Expiration time
  );
}
```

4.**Protect Routes Using Middleware**

```ts
import express from 'express';

const app = express();

// Protect an endpoint
app.get(
  '/protected',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    res.json({ message: 'You are authorized!', user: req.user });
  }
);
```

#### Best Practices When Using ``passport-jwt``

1.<span style="font-size: 14px; font-weight: bold">Use Short-Lived Tokens:</span>

  * Set the JWT expiration (exp) to a short time (e.g., 15 minutes) and implement a refresh token mechanism for re-issuing tokens securely.

2.<span style="font-size: 14px; font-weight: bold">Secure Token Storage:</span>

  * Store tokens securely on the client:
  * Use ``HttpOnly`` cookies for web applications (mitigates XSS attacks).
  * Avoid storing tokens in ``localStorage`` or ``sessionStorage`` unless necessary.

3.<span style="font-size: 14px; font-weight: bold">Validate Tokens on Each Request:</span>

* Ensure token signatures and expiration times are validated for every incoming request.

4.<span style="font-size: 14px; font-weight: bold">Token Revocation:</span>

* Implement a token blacklist or revocation mechanism (e.g., storing revoked tokens or sessions in a database) for high-security requirements.

5.<span style="font-size: 14px; font-weight: bold">Combine with Other Strategies:</span>

* Use passport-local for login and token issuance:
* Authenticate username/password using passport-local.
* Issue a JWT on successful login.

**Example Hybrid Flow: Combining ``passport-local`` with ``passport-jwt``**

1.**Install ``passport-local``**

```bash
bash
npm install passport-local
```

2.**Configure ``passport-local``**


```ts
TypeScript:

import { Strategy as LocalStrategy } from 'passport-local';

// Example local strategy
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await findUserByUsername(username); // Replace with your DB call
      if (!user || !validatePassword(user, password)) {
        return done(null, false, { message: 'Invalid credentials' });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);
```

3.**Login Route (Issue JWT)**

```ts
TypeScript:

app.post('/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err || !user) {
      return res.status(401).json({ message: info?.message || 'Unauthorized' });
    }

    // Generate token
    const token = generateToken(user);
    return res.json({ token });
  })(req, res, next);
});
```

<br />

#### Summary

<table>
<tr>
  <th>Feature</th>
  <th>Session-Based (passport-local)</th>
  <th>JWT-Based (passport-jwt))</th>
</tr>
<tr>
  <td style="font-size: 14px; font-weight: bold">Statefulness</td>
  <td style="font-size: 14px;">Requires session store</td>
  <td style="font-size: 14px;">Stateless</td>
</tr>
<tr>
  <td style="font-size: 14px; font-weight: bold">Scalability</td>
    <td style="font-size: 14px;">Limited</td>
  <td style="font-size: 14px;">Highly scalable</td>
</tr>
<tr>
  <td style="font-size: 14px; font-weight: bold">Security</td>
    <td style="font-size: 14px;">Centralized control</td>
  <td style="font-size: 14px;">Decentralized, token revocation needed</td>
</tr>
<tr>
<td style="font-size: 14px; font-weight: bold">Best Use Case</td>
  <td style="font-size: 14px;">Monolithic apps</td>v
  <td style="font-size: 14px;">Distributed apps, APIs</td>
</tr>
</table>

<br />

Was this page helpful?
<p style="background: purple; color: yellow; padding: 15px">If you find this article helpful, please feel free to share the link.</p>

Yes👍 No👎