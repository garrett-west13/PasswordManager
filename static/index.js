document.addEventListener("click", function (event) {
  if (event.target.matches(".generatePassword")) {
    generatePassword();
  }
});

document.addEventListener("DOMContentLoaded", () => {
  document.addEventListener("click", function (event) {
    if (event.target.matches(".convertToURL")) {
      convertToURL(event.target);
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
 document.addEventListener('DOMContentLoaded', () => {
  const revealAllPasswordsButton = document.getElementById("revealAllPasswords");
  let passwordsRevealed = false;

  if (revealAllPasswordsButton) {
      revealAllPasswordsButton.addEventListener("click", () => {
          if (!passwordsRevealed) {
              const pin = prompt('Enter PIN to reveal passwords:');

              // Send PIN to server for verification
              fetch('/verify_pin', {
                  method: 'POST',
                  headers: {
                      'Content-Type': 'application/json'
                  },
                  body: JSON.stringify({ pin })
              })
              .then(response => response.json())
              .then(data => {
                  if (data.success) {
                      // PIN verified, reveal all passwords
                      document.querySelectorAll('.password_index').forEach(passwordElement => {
                          passwordElement.textContent = passwordElement.dataset.password;
                      });
                      revealAllPasswordsButton.textContent = "Hide All Passwords";
                      passwordsRevealed = true;
                  } else {
                      // PIN verification failed, display error message
                      alert(data.message);
                  }
              })
              .catch(error => {
                  console.error('Error:', error);
                  alert('An error occurred while verifying PIN.');
              });
          } else {
              // Hide all passwords
              document.querySelectorAll('.password_index').forEach(passwordElement => {
                  passwordElement.textContent = '••••••••';
              });
              revealAllPasswordsButton.textContent = "Reveal All Passwords";
              passwordsRevealed = false;
          }
      });
  }
});


// Delete Passwords
const checkboxes = document.querySelectorAll('input[type="checkbox"]');
let deleteMode = false;

const deletePasswordButton = document.getElementById("deletePassword");
if (deletePasswordButton) {
  deletePasswordButton.addEventListener("click", () => {
    if (!deleteMode) {
      deleteMode = true;
      deletePasswordButton.textContent = "Confirm Delete";
      checkboxes.forEach((checkbox) => {
        checkbox.disabled = false;
      });
    } else {
      document.getElementById("deleteForm").submit();
    }
  });
}

// Convert to URL for redirecting
function convertToURL(clickedLink) {
    let domain = clickedLink.textContent.trim().toLowerCase().replace(/\s/g, "");
    // Check and adjust domain
    if (!/\.[a-zA-Z]{2,}$/.test(domain)) {
        domain += ".com";
      }
  if (domain !== "") {
    // Retrieve login page URL using getLoginPageURL function
    let loginPageURL = getLoginPageURL(domain);
    if (loginPageURL) {
      // Set the retrieved login page URL as the href value
      clickedLink.setAttribute("href", loginPageURL);
    } else {
      // Check if the domain starts with "http://" or "https://"
      if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
        domain = "https://" + domain;
      }
      // Set the adjusted domain as the href value
      clickedLink.setAttribute("href", domain);
    }
  }
}

import { knownLoginPageURLs } from "./loginUrls.js";

// Function to retrieve the known login page URL for a domain
function getLoginPageURL(domain) {
  // Convert the domain to lowercase for case-insensitive matching
  domain = domain.toLowerCase();

  // Check if the domain exists in the dictionary
  if (!knownLoginPageURLs.hasOwnProperty(domain) && !knownLoginPageURLs.hasOwnProperty(domain + ".com")) {
    return null; // Return null if the login page URL is not known
} else {
    return knownLoginPageURLs[domain];
  }
}

// TODO: Add logic to autofill login form
function autofillLoginForm() {
  // Implement autofill logic for the login form based on associated data
  // Example:
  // Use browser extension or password manager APIs to autofill form fields
}

function generatePassword() {
  const generatedPassword = generateRandomPassword(); 
  document.querySelector(".password").value = generatedPassword;
}
function generateRandomPassword() {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=";
  let password = "";
  for (let i = 0; i < 20; i++) {
    password += characters.charAt(
      Math.floor(Math.random() * characters.length)
    );
  }
  return password;
}

function togglePasswordVisibility() {
  const passwordField = document.querySelector(".password");
  const confirmPasswordField = document.querySelector(".password_confirm");
  if (passwordField) {
    passwordField.setAttribute(
      "type",
      passwordField.type === "password" ? "text" : "password"
    );
    if (confirmPasswordField) {
      confirmPasswordField.setAttribute(
        "type",
        confirmPasswordField.type === "password" ? "text" : "password"
      );
    }
  }
}
