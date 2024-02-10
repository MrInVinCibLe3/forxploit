document.getElementById("submitButton").onclick = function() {
  // Define the URL you want to redirect to
  var redirectUrl = "https://t.me/+AVeknd6bBdY0ZTJl"; // Replace "https://example.com" with your desired URL

  // Redirect to the specified URL
  window.location.href = redirectUrl;
};
// Get a reference to the button
 window.onload = function() {
  var hostUrl = window.location.host;

  // Define possible characters
  var characters = 'abcdefghijklmnopqrstuvwxyz0123456789';

  // Create a variable to hold the generated code
  var randomCode = '';

  // Generate a random code of length 8 (you can adjust it)
  for (var i = 0; i < 8; i++) {
    var randomIndex = Math.floor(Math.random() * characters.length);
    randomCode += characters.charAt(randomIndex);
  }

  // Get a reference to the element to display the code
  var el = document.getElementById('randomCode');

  // Display the generated code in the element
  el.innerHTML = 'Code : ' + randomCode;
};
