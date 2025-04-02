const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const {browse} = require('./bot');
const {URLSearchParams} = require('url');
const ip = require('ip');

const H_SITEKEY = process.env.H_SITEKEY ?? 'H_SITEKEY'
const H_SECRET = process.env.H_SECRET ?? 'H_SECRET'

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({extended:false}));

app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YAML Parser</title>
    <script src="https://cdn.jsdelivr.net/pyodide/v0.26.2/full/pyodide.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 50px;
        }
        textarea {
            width: 100%;
            height: 200px;
        }
        pre {
            background-color: #cccccc;
            padding: 20px;
            white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <h1>YAML Parser</h1>
    <textarea id="yaml" placeholder="- YAML"></textarea><br>
    <button id="parse">Parse</button>
    <h2>Output:</h2>
    <pre id="output"></pre>

    <script>
    let pyodide;
    async function init(){
    pyodide = await loadPyodide();
    await pyodide.loadPackage("pyyaml");
    runHash();
    }
    async function run(y){
    x = `+'`'+`import yaml
yaml.load("""`+`$`+`{y.replaceAll('"','')}""",yaml.Loader)`+'`'+`;
            try {
                output.textContent = await pyodide.runPythonAsync(x);
            } catch (e) {
                output.textContent = e;
            }
    }
        async function runHash() {
            const hash = decodeURIComponent(window.location.hash.substring(1));
            if (hash) {
                yaml.value = hash;
                run(hash);
            }
        }        
        parse.addEventListener("click", async () => {run(yaml.value)});
        onhashchange = runHash;
        onload = init;
    </script>
</body>
</html>
`);
});

app.get('/report', (req, res) => {
	res.send(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>YAML Parser</title>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
</head>
<body>
    <h1>Report</h1>
    <form method="POST">
      <table>
      <tr>
        <td>URL</td>
        <td><input name="url" size="70" /></td>
      </tr>
      </table>
      <div class="h-captcha" data-sitekey="${H_SITEKEY}"></div>
      <input type="submit" />
    </form>
  </body>
</html>`);
});

app.post('/report', async (req, res) => {
    const url = req.body.url;
    const hcaptchaResponse = req.body['h-captcha-response'];

    if(typeof url !== 'string'){
        res.status(400).send('Missing URL');
        return;
    }
    if(typeof hcaptchaResponse !== 'string'){
        res.status(400).send('Missing hCaptcha');
        return;
    }

    try{
        const postData = new URLSearchParams({
            secret: H_SECRET,
            response: hcaptchaResponse
        });
        const response = await axios.post('https://hcaptcha.com/siteverify', postData.toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        if(response.data.success){  //change this if you want to test locally without hCaptcha
        	browse(url);
            res.send('Thank you for your report.');
        }else{
            res.status(500).send('Error in hCaptcha');
        }
    }catch(e){
    	console.log(e);
        res.status(500).send('Error');
    }
});

app.post('/debug', (req, res) => {
    if(ip.isLoopback(req.ip) && req.cookies.debug === 'on'){
        const yaml = require('js-yaml');
        let schema = yaml.DEFAULT_SCHEMA.extend(require('js-yaml-js-types').all);
        try{
        	let input = req.body.yaml;
        	console.log(`Input: ${input}`);
        	let output = yaml.load(input, {schema});
        	console.log(`Output: ${output}`);
        	res.json(output);
        }catch(e){
        	res.status(400).send('Error');
        }
    }else{
        res.status(401).send('Unauthorized');
    }
});

app.listen(3000, () => {
    console.log('Server is running at http://localhost:3000');
});
