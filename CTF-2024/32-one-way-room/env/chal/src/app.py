from flask import Flask, request, render_template
import re

app = Flask(__name__)

# Correct answers (for example purposes)
correct_answers = {
    "uuid": "b2bc2958-9c47-495a-8bab-3bae83cf9ca4",
    "backdoor_url": "https://t.ly/backdoor.sh",
    "password": "nokiasummer1990",
    "deleted_file_flag": "flag{th3_fi13_sh411_b3_d313t3d}",
    "attacker_ip": "192.166.246.54"
}

def normalize_input(input_string):
    """
    Normalize the input by converting to lowercase and removing all non-alphanumeric characters.
    """
    # Convert to lowercase
    input_string = input_string.lower()
    # Remove all non-alphanumeric characters
    input_string = re.sub(r'[^a-z0-9]', '', input_string)
    return input_string

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_answers():
    # Get the user input from the form
    answers = {
        "uuid": request.form.get('uuid'),
        "backdoor_url": request.form.get('backdoor_url'),
        "password": request.form.get('password'),
        "deleted_file_flag": request.form.get('deleted_file_flag'),
        "attacker_ip": request.form.get('attacker_ip')
    }

    # Check answers after normalizing both the correct answers and user inputs
    all_correct = True
    results = {}

    for key, user_answer in answers.items():
        normalized_user_answer = normalize_input(user_answer)
        normalized_correct_answer = normalize_input(correct_answers[key])
        
        if normalized_user_answer == normalized_correct_answer:
            results[key] = "Correct"
        else:
            results[key] = "Incorrect"
            all_correct = False

    # Show the hidden flag if all answers are correct
    hidden_string = "hkcert24{h4v3_4_t4st3_0f_1inux_f0r3nsic_0r_b3ing_rickr011_4g4in}" if all_correct else ""

    return render_template('results.html', results=results, hidden_string=hidden_string)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
