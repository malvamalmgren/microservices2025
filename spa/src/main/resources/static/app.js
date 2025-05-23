const AUTH_SERVER_URL = 'http://localhost:9000';

const loginButton = document.getElementById('loginButton');
const logoutButton = document.getElementById('logoutButton');

if (loginButton) {
    loginButton.addEventListener('click', redirectToLogin);
}
if (logoutButton) {
    logoutButton.addEventListener('click', logout);
}

async function redirectToLogin() {

    const authUrl = new URL(`${AUTH_SERVER_URL}/oauth2/authorize`);

    window.location.href = authUrl.toString();
}

function showHidePasswordFun() {
    const passwordInput = document.getElementById("password");
    const toggleIcon = document.getElementById("showHidePassword");

    const isPassword = passwordInput.type === "password";
    passwordInput.type = isPassword ? "text" : "password";
    toggleIcon.textContent = isPassword ? "🙈" : "🙉";
}
