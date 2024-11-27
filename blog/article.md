<div style="width: 100%; background: black; padding: 10px; padding-left: 15px; top: 0; position: relative;" ><a href="../blog.html" style="color: white;">< Back</a></div>

# How to Host React App With Routes on GitHub Pages


<div class="article-header" >
<img src="../media/heroImage.png" alt="" width="40" style="margin-right: 10px; border-radius: 25px"/> Author: Emmanuel</div>  

**Date:**  2024-09-25
<br>

**In** this post, We are going to learn a simple technique to host a React app on the GitHub Pages,

Often as a beginner, it's almost certain you will run into this kind of issue at some point,  this can be very frustrating. Since React is arguably the most popular frontend library out there, you can find solutions on the internet to fix any react-related issues you may encounter as you develop your application. This is true because of React's robust user community. If you have stumbled upon this article, you should worry no more, today you will learn how to fix this problem by applying the simple steps in this article.

Before we dive in, let's quickly look at what we will learn in this article.

## Table of Contents

* Create a React App
* Install gh-pages
* Add Homepage to package.json
* Prepare your Routes
* Deploy to GitHub Pages

### Create a React App

First, create a new React app using [create-react-app](https://create-react-app.dev/docs/getting-started).

```bash
npx create-react-app my-app
cd my-app
```

### Install gh-pages

Next, install gh-pages package as a dev dependency. You can find more information about this and more in the deployment page of the [React documentation](https://create-react-app.dev/docs/deployment).

```bash
npm install gh-pages --save-dev
```

### Add Homepage to package.json

Add a homepage field to your package.json file as shown below.

```bash
{
  "name": "my-app",
  "version": "0.1.0",
  "homepage": "https://username.github.io/my-app",
  ...
}
```

**Prepare your Routes for GitHub Pages***

To add routes that work on GitHub Pages, you need to use HashRouter instead of BrowserRouter. Wrap the HashRouter around your routes including the Router as seen below in the App component or the index.js depending on where you place your routes.

```jsx
import { HashRouter as Router, Route } from 'react-router-dom';

function App() {
  return (
  <HashRouter>
      <Router>
          <Route path="#/" exact component={Home} />
          <Route path="#/about" component={About} />
          <Route path="#/contact" component={Contact} />
      </Router>
  </HashRouter>
  );
}
```

In the above code, we use the HashRouter instead of BrowserRouter from react-router-dom. The HashRouter uses the hash portion of the URL to create routes that work on GitHub Pages. After that, we created routes using the Route component from react-router-dom. The Route component renders a component based on the URL path. The path prop specifies the URL path and the component prop specifies the components to render when the path of the URL matches the path prop.

There is one more thing to do to make it work correctly. To address this we must make adjustments to the navigation component.

### Create Navigation Component

Next, create a navigation component if you have not yet created one, after you create the component, copy the code below and paste it inside or create navigation links using the Link component from react-router-dom or with an anchor if you prefer that.

```jsx
import { Link } from 'react-router-dom';

function Navigation() {
  return (
    <nav>
      <ul>
        <li> 
          <Link to="#/">Home</Link>
        </li>
        <li>
          <Link to="#/about">About</Link>
        </li>
        <li>
          <Link to="#/contact">Contact</Link>
        </li>
      </ul>
    </nav>
  );
}
```

*Now that we have created the navigation links using the Link component. The Link component creates a hyperlink to a specific route in the app, but wait a minute, we are using a hash symbol (#) before the route, why? Because we are using the HashRouter, we need to use the hash symbol before the forward slash to make it work on GitHub Pages, or else it will not work, and, that will result in a 404 error when you try to access the route directly.*

### Deploy to GitHub Pages

Finally, build your app and deploy it to GitHub Pages using these commands.

```bash
npm run build
npm run deploy
```

That's it! Your React app is now hosted on GitHub Pages and can route between pages successfully.

Was this page helpful?

Yes👍 No👎