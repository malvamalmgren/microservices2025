const AUTH_SERVER_URL = 'http://localhost:9000';
const RESOURCE_SERVER_URL = 'http://localhost:8000';
const CLIENT_ID = 'spa-client-id';
const REDIRECT_URI = 'http://localhost:8888/callback.html';
const SCOPES = 'openid read_resource';

const loginButton = document.getElementById('loginButton');
const logoutButton = document.getElementById('logoutButton');
const statusEl = document.getElementById('status');
const apiResponseEl = document.getElementById('apiResponse');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');

loginButton.addEventListener('click', redirectToLogin);
logoutButton.addEventListener('click', logout);

document.getElementById('apiJoke').addEventListener('click', () => callApi('jokes/random'));
document.getElementById('apiQuote').addEventListener('click', () => callApi('quotes/random'));

document.getElementById('registerForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await fetch(`${AUTH_SERVER_URL}/register`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: usernameInput.value,
        password: passwordInput.value
      })
    });
    usernameInput.value = '';
    passwordInput.value = '';
    alert('User registered successfully!');
  } catch (error) {
    console.error('Registration error:', error);
    alert('Registration failed.');
  }
});

document.addEventListener('DOMContentLoaded', updateUI);

async function redirectToLogin() {
  const codeVerifier = generateRandomString(64);
  sessionStorage.setItem('pkce_code_verifier', codeVerifier);

  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateRandomString(32);
  sessionStorage.setItem('oauth_state', state);

  const authUrl = new URL(`${AUTH_SERVER_URL}/oauth2/authorize`);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', SCOPES);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', state);

  window.location.href = authUrl;
}

function generateRandomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  return Array.from({ length }, () => chars.charAt(Math.floor(Math.random() * chars.length))).join('');
}

async function generateCodeChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(digest);
}

function base64UrlEncode(buffer) {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

window.handleCallback = handleCallback;


async function handleCallback() {
    console.log("Handling callback...");
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const receivedState = params.get('state');

    const storedState = sessionStorage.getItem('oauth_state');
    const codeVerifier = sessionStorage.getItem('pkce_code_verifier');

    if (!code) {
        statusEl.textContent = 'Error: No authorization code received.';
        console.error('No authorization code.');
        return;
    }

    if (receivedState !== storedState) {
        statusEl.textContent = 'Error: State mismatch. Possible CSRF attack.';
        console.error('State mismatch.');
        sessionStorage.removeItem('oauth_state');
        sessionStorage.removeItem('pkce_code_verifier');
        return;
    }

    sessionStorage.removeItem('oauth_state');
    sessionStorage.removeItem('pkce_code_verifier');

    try {
        const tokenResponse = await fetch(`${AUTH_SERVER_URL}/oauth2/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: REDIRECT_URI,
                client_id: CLIENT_ID,
                code_verifier: codeVerifier
            })
        });

        if (!tokenResponse.ok) {
            const errorData = await tokenResponse.json();
            throw new Error(`Token exchange failed: ${tokenResponse.status} - ${errorData.error_description || errorData.error || 'Unknown error'}`);
        }

        const tokenData = await tokenResponse.json();
        localStorage.setItem('access_token', tokenData.access_token);
        if (tokenData.refresh_token) {
            localStorage.setItem('refresh_token', tokenData.refresh_token);
        }
        if (tokenData.id_token) {
            localStorage.setItem('id_token', tokenData.id_token);
        }

        window.location.href = '/index.html';

    } catch (error) {
        console.error('Error exchanging code for token:', error);
        if (document.body) {
            document.body.innerHTML = `<p>Error during login: ${error.message}. <a href="/index.html">Go back</a></p>`;
        } else if (statusEl) {
            statusEl.textContent = `Error during login: ${error.message}`;
        }
    }
}

async function callApi(endpoint) {
  const token = localStorage.getItem('access_token');
  try {
    const resp = await fetch(`${RESOURCE_SERVER_URL}/${endpoint}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (resp.status === 401) {
      statusEl.textContent = 'Unauthorized. Please log in again.';
      return;
    }
    if (!resp.ok) throw new Error(resp.statusText);
    apiResponseEl.textContent = await resp.text();
  } catch (error) {
    console.error('API error:', error);
    statusEl.textContent = 'API request failed.';
  }
}

function logout() {
  ['access_token', 'refresh_token', 'id_token'].forEach(key => localStorage.removeItem(key));
  updateUI();
}

function updateUI() {
  const token = localStorage.getItem('access_token');
  if (token) {
    statusEl.textContent = 'Logged in.';
    loginButton.style.display = 'none';
    logoutButton.style.display = 'inline-block';
  } else {
    statusEl.textContent = 'Not logged in.';
    loginButton.style.display = 'inline-block';
    logoutButton.style.display = 'none';
    apiResponseEl.textContent = '';
  }
}
