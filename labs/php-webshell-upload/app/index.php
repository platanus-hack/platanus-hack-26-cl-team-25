<?php
// Toy storefront "profile photo" upload — deliberately missing validation.
?>
<!doctype html><title>ACME Panel</title>
<h1>ACME operator panel</h1>
<form method="post" action="/upload.php" enctype="multipart/form-data">
  <input type="file" name="avatar"><button>Upload avatar</button>
</form>
