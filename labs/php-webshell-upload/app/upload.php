<?php
// VULNERABILITY: stores the uploaded file under the webroot with its original
// name and extension, with no type/content check. A .php upload becomes executable.
$dir = __DIR__ . '/uploads/';
if (!empty($_FILES['avatar']['name'])) {
    $dest = $dir . basename($_FILES['avatar']['name']);
    move_uploaded_file($_FILES['avatar']['tmp_name'], $dest);
    echo "stored:/uploads/" . basename($_FILES['avatar']['name']);
} else {
    http_response_code(400); echo "no file";
}
