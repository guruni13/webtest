<html>
   
<?php
   setcookie("name", "SHADOW2639", ['SameSite' => 'Strict']);
?>
   <body>
      <center><h2>Setting Cookies with "SameSite:Strict"</h2>
      <br>
      <h3> Refresh the page once to set the cookie</h3>
      <?php
         echo "<h4>"."Cookie Value set to : " .$_COOKIE["name"]. "</h4>";
         ?>
         </center>
   </body>
   
</html>

