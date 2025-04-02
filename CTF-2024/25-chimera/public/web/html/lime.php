<?php
    class CitrusWorkspace {
        function __construct($root) {
            if (!is_dir($root)) {
                mkdir($root, 0755);
            }
            $this->root = $root;
        }

        function create($filename, $symlink=0, $target="") {
            $this->validate_filename($filename);

            if ($symlink === 0) {
                @file_put_contents($this->root.$filename, "");
            }
            else {
                @symlink($target, $this->root.$filename);

                try {
                    if (str_contains(@readlink($this->root.$filename), "/") || str_contains(@readlink($this->root.$filename), "..")) {
                        throw new Exception("Trying to hack?");
                    }
                }
                catch (Exception $e) {
                    @unlink($this->root.$filename);
                    throw $e;
                }
            }
        }

        function read($filename) {
            $this->validate_filename($filename);

            sleep(5);

            chdir($this->root);
            $buf = @file_get_contents($this->resolve_symlink($filename));
            return $buf;
        }

        function write($filename, $data) {
            $this->validate_filename($filename);

            sleep(5);

            chdir($this->root);
            @file_put_contents($this->resolve_symlink($filename), $data);
        }

        function delete($filename) {
            $this->validate_filename($filename);
            $this->assert_file_exists($this->root.$filename);

            @unlink($this->root.$filename);
        }

        function list() {
            $res = array();

            $ls = array_diff(scandir($this->root), array("..", "."));
            foreach($ls as $k => $v) {
                if (is_link($this->root.$v)) {
                    $res[$v] = "Symlink to ".@readlink($this->root.$v);
                }
                else
                    $res[$v] = "File";
            }

            return $res;
        }

        function validate_filename($filename) {
            if (preg_match('/[^a-z0-9]/i', $filename)) {
                throw new Exception("Filename only contain alphanumerics.");
            }
        }

        function assert_file_exists($filename) {
            if (file_exists($filename) === false && is_link($filename) === false) {
                throw new Exception("File not found.");
            }
        }

        function resolve_symlink($filename) {
            if (is_link($filename)) {
                return @readlink($filename);
            }
            return $filename;
        }

    }
?>