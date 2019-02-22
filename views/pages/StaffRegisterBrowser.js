<html>

<head>
  <title>Naylor Learning Center - Register Browser</title>
  <link rel='stylesheet' href='/stylesheets/style.css' />
  <script type="text/javascript">
    function validateForm() {
      var d = new Date();
      d.setTime(d.getTime() + (365 * 24 * 60 * 60 * 1000));
      document.cookie = "location=" + myForm.location.value + "; expires=" + d.toUTCString() + "; path=/";
    }
  </script>
  
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.0/jquery.min.js"></script>

</head>

<body>

  <h1>Naylor Learning Center - Register Browser</h1>

  <p>This form will register this browser to permit NLC attendance tracking.</p>
  <p>When a student checks in with this browser, their visit will be marked with the location that you enter below.</p>
  
  <script src="/javascripts/formCheck.js"></script>
  
  <form name="myForm" onsubmit="return validateForm()" method="post" action="#">
    Location Name:
    <input type="text" autofocus name="location" maxlength="255" required>
    <input type="submit" value="Submit">
  </form>

</body>

</html>