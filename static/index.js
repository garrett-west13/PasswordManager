
    document.addEventListener('click', function(event) {
        if (event.target.matches('.generatePassword')) {
          generatePassword();
        }
      });

      document.addEventListener('DOMContentLoaded', () => {
        document.addEventListener('click', function(event) {
            if (event.target.matches('.convertToURL')) {
                convertToURL(event.target); // Pass the clicked link as an argument
            }
        });
    });
      const togglePasswordButton = document.querySelector('.togglePassword');
        if (togglePasswordButton) {
            togglePasswordButton.addEventListener("click", () => {
            togglePasswordVisibility();
        });
    }
 
 // Add event listener to reveal all passwords
 const revealAllPasswordsButton = document.getElementById("revealAllPasswords");
 if (revealAllPasswordsButton) {
   revealAllPasswordsButton.addEventListener("click", () => {
     console.log("Button clicked!");
     const pin = prompt('Enter PIN to reveal passwords:');

    // Send PIN to server for verification
    fetch('/verify_pin', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            pin
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // PIN verified, reveal all passwords
            document.querySelectorAll('.password_index').forEach(passwordElement => {
                passwordElement.textContent = passwordElement.dataset.password;
            });
        } else {
            // PIN verification failed, display error message
            alert(data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while verifying PIN.');
    });
 });
 };

const checkboxes = document.querySelectorAll('input[type="checkbox"]');
let deleteMode = false;

const deletePasswordButton = document.getElementById("deletePassword");
if (deletePasswordButton) {
  deletePasswordButton.addEventListener("click", () => {
    if (!deleteMode) {
        deleteMode = true;
        deletePasswordButton.textContent = "Confirm Delete";
        checkboxes.forEach(checkbox => {
            checkbox.disabled = false;
        });
    } else {
        if (confirm("Are you sure you want to delete the selected passwords?")) {
            document.getElementById("deleteForm").submit();
        }
    }
});
}


function convertToURL(clickedLink) {
    let domain = clickedLink.textContent.trim(); // Get the domain from the clicked link
    if (domain !== "") {
        // Retrieve login page URL using getLoginPageURL function
        let loginPageURL = getLoginPageURL(domain);
        if (loginPageURL) {
            // Set the retrieved login page URL as the href value
            clickedLink.setAttribute('href', loginPageURL);
        } else {
            // Check and adjust domain
            if (!/\.[a-zA-Z]{2,}$/.test(domain)) {
                domain += ".com";
            }
            // Check if the domain starts with "http://" or "https://"
            if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
                domain = "https://" + domain;
            }
            // Set the adjusted domain as the href value
            clickedLink.setAttribute('href', domain);
        }
    }
}

import { knownLoginPageURLs } from './loginUrls.js';

// Function to retrieve the known login page URL for a domain
function getLoginPageURL(domain) {
    // Convert the domain to lowercase for case-insensitive matching
    domain = domain.toLowerCase();

    // Check if the domain exists in the dictionary
    if (knownLoginPageURLs.hasOwnProperty(domain)) {
        return knownLoginPageURLs[domain];
    } else {
        return null; // Return null if the login page URL is not known
    }
}

function autofillLoginForm() {
    // Implement autofill logic for the login form based on associated data
    // Example:
    // Use browser extension or password manager APIs to autofill form fields
}

function generatePassword() {
    // Generate password logic
    const generatedPassword = generateRandomPassword(); // Replace with your password generation logic
    document.querySelector(".password").value = generatedPassword;
}
function generateRandomPassword() {
    // Generate a random password
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=";
    let password = "";
    for (let i = 0; i < 20; i++) {
        password += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return password;
}

function togglePasswordVisibility() {
    const passwordField = document.querySelector(".password");
    const confirmPasswordField = document.querySelector(".password_confirm");
    if (passwordField && confirmPasswordField) {
        if (passwordField.type === "password" && confirmPasswordField.type === "password") {
            passwordField.setAttribute('type', 'text');
            confirmPasswordField.setAttribute('type', 'text');
        } else {
            passwordField.setAttribute('type', 'password');
            confirmPasswordField.setAttribute('type', 'password');
        }
    }
}
