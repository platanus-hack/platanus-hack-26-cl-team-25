import sys; sys.path.insert(0, "/home/ubuntu/repos/platanus-hack-26-cl-team-25")
from gateway import l0, classifier
# 1) attacker recon (typical first move before dropping a shell)
recon = ["/wp-login.php","/xmlrpc.php","/config.php","/admin.php","/phpmyadmin","/.env","/.git/config","/server-status"]
print("recon paths the honeypot (l0) engages with decoys:")
for p in recon:
    print(f"   {p:22} scanner={l0.is_scanner_path(p)}")
# 2) the webshell upload itself, through stage-1
body = (b'--X\r\nContent-Disposition: form-data; name="avatar"; filename="shell.php"\r\n'
        b'Content-Type: image/png\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--X--\r\n')
fields = classifier.parse_multipart_fields(body, "multipart/form-data; boundary=X")
print(f"\nmultipart text fields stage-1 sees in the upload: {fields}  (the .php file body is ignored)")
print(f"traversal in '/uploads/shell.php'? {classifier.traversal_in_path('/uploads/shell.php')}")
