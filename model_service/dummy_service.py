from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/v1/user', methods=['GET', 'POST'])
def handle_user():
    """ A simple endpoint that echoes back request info. """
    response_data = {
        "message": "Request successfully received by upstream service!",
        "method": request.method,
        "path": request.path,
        "query_params": request.args.to_dict(),
        "body": request.get_json(silent=True) or request.form.to_dict() or "No JSON/Form body"
    }
    return jsonify(response_data), 200

if __name__ == '__main__':
    app.run(port=8081, debug=True)