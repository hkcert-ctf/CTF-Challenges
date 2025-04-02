<?php
session_start();
require_once("lime.php");

$dirname= md5(session_id());
$workspace = new CitrusWorkspace("/tmp/$dirname/");

$mode = !empty($_POST["mode"]) ? $_POST["mode"] : null;
$filename = !empty($_POST["filename"]) ? $_POST["filename"] : null;

$error = null;
try {
    if (($_SERVER["REQUEST_METHOD"] === "POST") && ($mode === null || $filename === null)) {
        throw new Exception("mode or filename cannot be empty.");
    }

    switch($mode) {
        case "create":
            $symlink = isset($_POST["symlink"]) ? 1 : 0;
            $target = !empty($_POST["target"]) ? $_POST["target"] : null;
            $workspace->create($filename, $symlink, $target);
            break;

        case "read":
            $contents = $workspace->read($filename);
            break;

        case "write":
            $data = !empty($_POST["data"]) ? $_POST["data"] : "";
            $workspace->write($filename, $data);
            break;

        case "delete":
            $workspace->delete($filename);
            break;
    }
} catch(Exception $e) {
    $error = $e->getMessage();
}

$ls = $workspace->list();
?>

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

        <link rel="stylesheet" href="css/styles.css" />
        <link rel="stylesheet" href="css/fontawesome/all.css" />
        <link rel="icon" href="res/icon.png" />

        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css"
              integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"
                integrity="sha512-bLT0Qm9VnAYZDflyKcBaQ2gg0hSYNQrJ8RilYldYQ1FxQYoCLtUjuuRuZo+fjqhx/qtq/1itJ0C2ejDxltZVFg=="
                crossorigin="anonymous"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js"
                integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q"
                crossorigin="anonymous"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"
                integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl"
                crossorigin="anonymous"></script>

        <title>Chimera</title>
    </head>

    <body>
        <div class="container">
            <h2 class="mt-5">Citrus Workspace</h2>
            <?php if (!empty($error)) { ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <strong>Error: </strong><?= htmlspecialchars($error) ?>
                    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
            <?php } ?>
            <?php if (isset($contents)) { ?>
                <div class="card">
                    <div class="card-header">Contents of <?= htmlspecialchars($filename) ?></div>
                    <div class="card-body">
                        <p class="card-text"><?= nl2br(htmlspecialchars($contents)) ?></p>
                    </div>
                </div>
            <?php } ?>

            <!-- Create -->
            <hr>
            <h4 class="mt-1">Create a File</h4>
            <form method="POST" action="/citrus.php">
                <div class="form-group">
                    <label for="new-name">Filename</label>
                    <input id="new-name" type="text" class="form-control" placeholder="filename" name="filename" required>
                </div>
                <div class="form-group">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="symlink" value="" id="new-type">
                        <label class="form-check-label" for="new-type">Symbolic Link</label>
                    </div>
                </div>
                <div class="form-group" id="new-target-group">
                    <label for="new-target">Target</label>
                    <input id="new-target" type="text" class="form-control" placeholder="target path" name="target">
                </div>
                <input type="hidden" name="mode" value="create">
                <button type="submit" class="btn btn-primary">Create File</button>
                <script>
                 $(function() {
                     $('[id=new-target-group]').hide();
                     $('[name="symlink"]:checkbox').change(function() {
                         $('[id=new-target-group]').fadeToggle();
                     });
                 });
                </script>
            </form>

            <!-- File List -->
            <hr>
            <h4 class="mt-1">Your Files</h4>
            <div id="workspace">
                <?php $id = 0; ?>
                <?php foreach($ls as $filename => $attribute) { ?>
                    <div class="card">
                        <div class="card-header" id="file-<?= $id ?>-head">
                            <h5 class="mb-0">
                                <button class="btn btn-link" data-toggle="collapse" aria-expanded="false" 
                                        data-target="#file-<?= $id ?>-body" aria-controls="file-<?= $id ?>-body">
                                    <?= htmlspecialchars($filename) ?>
                                </button>
                            </h5>
                        </div>
                    </div>
                    <div id="file-<?= $id ?>-body" class="collapse" aria-labelledby="file-<?= $id ?>-head" data-parent="#workspace">
                        <div class="card-body">
                            <p>Type: <?= htmlspecialchars($attribute) ?></p>
                            <form method="POST" action="/citrus.php">
                                <input type="hidden" name="filename" value="<?= htmlspecialchars($filename); ?>">
                                <input type="hidden" name="mode" value="read">
                                <input type="submit" class="btn btn-success" value="Read">
                            </form>
                            <hr>
                            <form method="POST" action="/citrus.php">
                                <div class="form-group">
                                    <label for="edit-<?= $id ?>">Contents</label>
                                    <textarea class="form-control" id="edit-<?= $id ?>" name="data" rows="3"></textarea>
                                </div>
                                <input type="hidden" name="filename" value="<?= htmlspecialchars($filename); ?>">
                                <input type="hidden" name="mode" value="write">
                                <input type="submit" class="btn btn-success" value="Write">
                            </form>
                            <hr>
                            <form method="POST" action="/citrus.php">
                                <input type="hidden" name="filename" value="<?= htmlspecialchars($filename); ?>">
                                <input type="hidden" name="mode" value="delete">
                                <input type="submit" class="btn btn-danger" value="Delete">
                            </form>
                        </div>
                    </div>
                    <?php $id++; ?>
                <?php } ?>
            </div>
        </div>
    </body>
</html>
