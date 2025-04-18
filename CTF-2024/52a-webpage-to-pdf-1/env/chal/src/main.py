from flask import Flask, request, make_response, redirect, render_template_string
import uuid
import requests
from execute_command import execute_command

app = Flask(__name__, static_folder='')

@app.route('/', methods=['GET'])
def index():
    # HTML template for the form
    FORM_TEMPLATE = '''
    <!doctype html>
    <html>
    <head><title>Webpage to PDF</title></head>
    <body>
        <h1>Webpage to PDF</h1>
        <form action="{{ url_for('process_url') }}" method="post">
            <label for="url">Enter URL:</label>
            <input type="url" id="url" name="url" required>
            <button type="submit">Submit</button>
        </form>
    </body>
    </html>
    '''

    response = make_response(render_template_string(FORM_TEMPLATE))

    # Generate a session ID if it doesn't exist
    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = str(uuid.uuid4())
        response.set_cookie('session_id', session_id)

    return response

@app.route('/process', methods=['POST'])
def process_url():
    # Get the session ID of the user
    session_id = request.cookies.get('session_id')
    html_file = f"{session_id}.html"
    pdf_file = f"{session_id}.pdf"

    # Get the URL from the form
    url = request.form['url']
    
    # Download the webpage
    response = requests.get(url)
    response.raise_for_status()

    with open(html_file, 'w') as file:
        file.write(response.text)

    # Make PDF
    stdout, stderr, returncode = execute_command(f'wkhtmltopdf {html_file} {pdf_file}')

    if returncode != 0:
        return f"""
        <h1>Error</h1>
        <pre>{stdout}</pre>
        <pre>{stderr}</pre>
        """
        
    return redirect(pdf_file)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

