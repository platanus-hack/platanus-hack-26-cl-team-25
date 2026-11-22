# Review notes

Unlike `victim/` and `examples/tareas-node`, **no defect is planted**: the app is OpenEMR v8_2_0 exactly as
released (`fetch.py` verifies the commit and that the tree equals the tag; the image's PHP files were verified
byte-identical to the tag).

Surfaces the gateway and the shadow watch most closely (all real OpenEMR 8.2.0 code):

| Surface | Route | Oracle that would fire |
|---|---|---|
| patient search / finder | `interface/main/finder/*.php`, `patient_select.php` | `sql` |
| documents | `controller.php?document&retrieve` | `file` |
| REST / FHIR API | `/apis/default/api/*`, `/apis/default/fhir/*` | `sql`, `owner` (account data) |
| administration | `interface/super/edit_globals.php`, `usergroup_admin.php`, `main/backup.php` | `proc`, `file`, ACL in OpenEMR |
| login | `interface/main/main_screen.php?auth=login` | (password is `x-sensitive`) |

Positive detections were verified end to end with a test-only fixture mounted into a shadow clone by the E2E
harness (never part of a release).
