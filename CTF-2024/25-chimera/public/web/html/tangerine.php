<!-- credit: ozetta -->

<?php 
class Marmalade {
    var $spice;
    var $salt;

    function __construct($spice, $salt = "") {
        $this->spice = $spice; 
        $this->salt = $salt; 
    }

    function __destruct() {
        $GLOBALS["file"] = @($this->salt . "file")(...$this->spice);
    }

    function __toString() {
        return @(string) $this->salt;
    }
}

// ($_=@$_GET["🍊"]) ? new Marmalade([$_]) : (isset($_) ? new Marmalade([$_=@$_FILES[0]["tmp_name"], "tmp/" . new Marmalade([$_]) . hash($_="sha256", @implode($_, $file)) . ".$_"], "move_uploaded_") : new Marmalade([__FILE__], "highlight_"));
?>
