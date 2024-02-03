    // Get a reference to the button
    var button = document.getElementById("generate");

    var hostUrl = window.location.host;
    
    // Run the function on button click
    button.onclick = function generate() {
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
      el.innerHTML = 'Your Code is : ' + '<br>' + randomCode + '<br>' + 'Site : '+ '<br>' + hostUrl;
    }
