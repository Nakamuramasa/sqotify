<template>
    <div id="background">
        <div id="loginContainer">
            <div id="inputContainer">
                <form id="loginForm">
                    <h2>Login to your acount</h2>
                    <p>
                        <label for="loginUsername">Username</label>
                        <input type="text" name="loginUsername" id="loginUsername" placeholder="JohnSmith" value="" required>
                    </p>
                    <p>
                        <label for="loginPassword">Password</label>
                        <input type="password" name="loginPassword" id="loginPassword" placeholder="Your password" required>
                    </p>

                    <button type="submit" name="loginButton">LOG IN</button>

                    <div class="hasAccountText">
                        <span id="hideLogin">Don't have an account yet? Sign up here.</span>
                    </div>
                </form>

                <form action="register.php" id="registerForm" method="POST">
                    <h2>Create your free account</h2>
                    <p>
                        <label for="username">Username</label>
                        <input type="text" name="username" id="username" placeholder="JohnSmith" value="" required>
                    </p>

                    <p>
                        <label for="firstName">First name</label>
                        <input type="text" name="firstName" id="firstName" placeholder="john" value="" required>
                    </p>

                    <p>
                        <label for="lastName">Last name</label>
                        <input type="text" name="lastName" id="lastName" placeholder="smith" value="<?php getInputValue('lastName') ?>" required>
                    </p>

                    <p>
                        <label for="email">Email</label>
                        <input type="email" name="email" id="email" placeholder="john@example.com" value="" required>
                    </p>

                    <p>
                        <label for="email2">Confirm email</label>
                        <input type="email" name="email2" id="email2" placeholder="john@example.com" value="" required>
                    </p>

                    <p>
                        <label for="password">Password</label>
                        <input type="password" name="password" id="password" placeholder="Your password" required>
                    </p>

                    <p>
                        <label for="password2">Confirm password</label>
                        <input type="password" name="password2" id="password2" placeholder="Your password" required>
                    </p>

                    <button type="submit" name="registerButton">SIGN UP</button>

                    <div class="hasAccountText">
                        <span id="hideRegister">Already have an account? Click here.</span>
                    </div>
                </form>
            </div>

            <div id="loginText">
                <h1>Get great music, right now</h1>
                <h2>Listen to loads of songs for free</h2>
                <ul>
                    <li>Discover music you'll fall in love with</li>
                    <li>Create your own playlists</li>
                    <li>Follow artists to keep up to date</li>
                </ul>
            </div>

        </div>
    </div>
</template>

<script>
export default {
    
}
</script>

<style>
/* @import "./css/register/css"; */
</style>