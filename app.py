import os
import time
import math
from flask import Flask, request, render_template, jsonify, send_from_directory, Response
from algorithms import camellia


UPLOAD_FOLDER = 'files'


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/progress-status')
def progress_query():
    def generate():
        camellia.progress = 0
        while camellia.progress < 100:
            time.sleep(0.5)
            yield 'data:' + '{"progress": "' + str(camellia.progress) + '"}' + '\n\n'

    return Response(generate(), mimetype='text/event-stream')


@app.route('/camellia', methods=['POST'])
def camellia_cipher():
    try:
        data_value = request.files['file']
        key = request.form['key']
        c0 = request.form['c0']
        key_size = int(request.form['key_size'])
        mode = request.form['mode']
        decode = request.form['decode']

        if data_value:
            filename = data_value.filename
            data = data_value.read()

            if len(key) == 0:
                raise ValueError("Empty key")
            if mode != 'ecb' and len(c0) == 0:
                raise ValueError("Empty c0 vector")

            c0 = c0[:16]
            key = (key * key_size)[:key_size]
            print(len(key.encode('utf-8')))

            blocks_count = math.ceil(len(data) / 16)
            count = 0

            if decode == 'true':
                camellia_algorithm = camellia.Camellia(key.encode('utf-8'), dec=True)
            else:
                camellia_algorithm = camellia.Camellia(key.encode('utf-8'), dec=False)

            if mode == 'ecb':
                cipher = camellia.ECB(camellia_algorithm)
            elif mode == 'cbc':
                cipher = camellia.CBC(camellia_algorithm, c0.encode('utf-8'))
            elif mode == 'ofb':
                cipher = camellia.OFB(camellia_algorithm, c0.encode('utf-8'))
            elif mode == 'cfb':
                cipher = camellia.CFB(camellia_algorithm, c0.encode('utf-8'))

            if decode == 'true':
                res = cipher.decode(data)
            else:
                res = cipher.encode(data)

            path = os.path.join(app.config['UPLOAD_FOLDER'], ('(Camellia)' + filename))

            with open(path, 'wb') as f:
                for x in res:
                    f.write(x)
                    count += 1
                    camellia.progress = math.trunc(count / blocks_count * 100)

            return jsonify({'path': r'http://localhost:5000/uploads/' + ('(Camellia)' + filename)})
        else:
            return jsonify({'error': 'Choose some file'})
    except Exception as ex:
        return jsonify({'error': str(ex)})


if __name__ == '__main__':
    app.run()
