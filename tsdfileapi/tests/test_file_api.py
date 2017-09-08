
"""
Exploring Transfer-Encoding: chunked with a minimal python client.

From: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding

Data is sent in a series of chunks. The Content-Length header is omitted in this
case and at the beginning of each chunk you need to add the length of the current
chunk in hexadecimal format, followed by '\r\n' and then the chunk itself, followed
by another '\r\n'.

The terminating chunk is a regular chunk, with the exception that its length is zero.
It is followed by the trailer, which consists of a (possibly empty) sequence of
entity header fields.

E.g.

HTTP/1.1 200 OK
Content-Type: text/plain
Transfer-Encoding: chunked

7\r\n
Mozilla\r\n
9\r\n
Developer\r\n
7\r\n
Network\r\n
0\r\n
\r\n

tornado
so with tornado it _just works_ - but not the naive impl
the async method write data to the file, while waiting for the rest
this is _exactly what the video streaming needs.
behind nginx you need to set the following:
proxy_http_version 1.1;
proxy_request_buffering off;

From bdarnell:
sending an error requires a little-used feature of HTTP called "100-continue".
If the client supports 100-continue (curl-based clients do by default for large POSTS;
most others don't. I don't know if curl uses 100-continue with chunked requests)
and the tornado service uses @stream_request_body, then sending an error response
from prepare() will be received by the client before the body is uploaded

On 100-continue:
https://tools.ietf.org/html/rfc7231#page-50

So the HTTP Client should implement this...
Some background on python2.7 and requests
https://github.com/kennethreitz/requests/issues/713

"""
import hashlib
import click
import logging
import httplib
import requests
import string
import time
import sys
import json
import os
import unittest
import yaml
from datetime import datetime

from tokens import IMPORT_TOKENS, EXPORT_TOKENS

# seems like the steaming ono=ly works with this in place
# don't really understand that
httplib.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


def lazy_file_reader(filename):
    with open(filename, 'r+') as f:
        while True:
            line = f.readline()
            if line == '':
                break
            else:
                yield line


def md5sum(filename, blocksize=65536):
    hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()


class TestFileApi(unittest.TestCase):


    @classmethod
    def setUpClass(cls):
        try:
            with open(sys.argv[1]) as f:
                cls.config = yaml.load(f)
        except Exception as e:
            print e
            print "Missing config file?"
            sys.exit(1)
        cls.base_url = 'http://localhost' + ':' + str(cls.config['port'])
        cls.data_folder = cls.config['data_folder']
        cls.example_csv = os.path.normpath(cls.data_folder + '/example.csv')
        cls.example_codebook = json.loads(open(os.path.normpath(cls.data_folder + '/example-ns.json')).read())
        cls.uploads_folder = cls.config['uploads_folder']
        # all endpoints
        cls.upload = cls.base_url + '/upload'
        cls.list = cls.base_url + '/list'
        cls.checksum = cls.base_url + '/checksum'
        cls.stream = cls.base_url + '/stream'
        cls.upload_stream = cls.base_url + '/upload_stream'
        cls.test_project = '/p19'


    @classmethod
    def tearDownClass(cls):
        uploaded_files = os.listdir(cls.uploads_folder)
        test_files = os.listdir(cls.config['data_folder'])
        today = datetime.fromtimestamp(time.time()).isoformat()[:10]
        for file in uploaded_files:
            if (file in test_files) or (today in file) or (file in [ 'streamed-example.csv',
                'uploaded-example.csv', 'uploaded-example-2.csv', 'uploaded-example-3.csv',
                'streamed-not-chunked' ]):
                try:
                    os.remove(os.path.normpath(cls.uploads_folder + '/' + file))
                except OSError as e:
                    logging.error(e)
                    continue
        # TODO remove sqlite db

    # Import Auth
    #------------

    def test_A_mangled_valid_token_rejected(self):
        headers = { 'Authorization': 'Bearer ' + IMPORT_TOKENS['MANGLED_VALID'] }
        files = {'file': ('example.csv', open(self.example_csv))}
        resp1 = requests.get(self.list, headers=headers)
        self.assertEqual(resp1.status_code, 401)
        resp2 = requests.get(self.checksum, headers=headers)
        self.assertEqual(resp2.status_code, 401)
        resp3 = requests.post(self.upload, headers=headers, files=files)
        self.assertEqual(resp3.status_code, 401)
        resp4 = requests.post(self.stream, headers=headers, files=files)
        self.assertEqual(resp4.status_code, 401)
        resp5 = requests.post(self.upload_stream, headers=headers, files=files)
        self.assertEqual(resp5.status_code, 401)
        resp6 = requests.patch(self.upload, headers=headers, files=files)
        self.assertEqual(resp6.status_code, 401)
        resp7 = requests.put(self.upload, headers=headers, files=files)
        self.assertEqual(resp7.status_code, 401)


    def test_B_invalid_signature_rejected(self):
        headers = { 'Authorization': 'Bearer ' + IMPORT_TOKENS['INVALID_SIGNATURE'] }
        files = {'file': ('example.csv', open(self.example_csv))}
        resp1 = requests.get(self.list, headers=headers)
        self.assertEqual(resp1.status_code, 401)
        resp2 = requests.get(self.checksum, headers=headers)
        self.assertEqual(resp2.status_code, 401)
        resp3 = requests.post(self.upload, headers=headers, files=files)
        self.assertEqual(resp3.status_code, 401)
        resp4 = requests.post(self.stream, headers=headers, files=files)
        self.assertEqual(resp4.status_code, 401)
        resp5 = requests.post(self.upload_stream, headers=headers, files=files)
        self.assertEqual(resp5.status_code, 401)
        resp6 = requests.patch(self.upload, headers=headers, files=files)
        self.assertEqual(resp6.status_code, 401)
        resp7 = requests.put(self.upload, headers=headers, files=files)
        self.assertEqual(resp7.status_code, 401)


    def test_C_token_with_wrong_role_rejected(self):
        headers = { 'Authorization': 'Bearer ' + IMPORT_TOKENS['WRONG_ROLE'] }
        files = {'file': ('example.csv', open(self.example_csv))}
        resp1 = requests.get(self.list, headers=headers)
        self.assertEqual(resp1.status_code, 401)
        resp2 = requests.get(self.checksum, headers=headers)
        self.assertEqual(resp2.status_code, 401)
        resp3 = requests.post(self.upload, headers=headers, files=files)
        self.assertEqual(resp3.status_code, 401)
        resp4 = requests.post(self.stream, headers=headers, files=files)
        self.assertEqual(resp4.status_code, 401)
        resp5 = requests.post(self.upload_stream, headers=headers, files=files)
        self.assertEqual(resp5.status_code, 401)
        resp6 = requests.patch(self.upload, headers=headers, files=files)
        self.assertEqual(resp6.status_code, 401)
        resp7 = requests.put(self.upload, headers=headers, files=files)
        self.assertEqual(resp7.status_code, 401)


    def test_D_timed_out_token_rejected(self):
        headers = { 'Authorization': 'Bearer ' + IMPORT_TOKENS['TIMED_OUT'] }
        files = {'file': ('example.csv', open(self.example_csv))}
        resp1 = requests.get(self.list, headers=headers)
        self.assertEqual(resp1.status_code, 401)
        resp2 = requests.get(self.checksum, headers=headers)
        self.assertEqual(resp2.status_code, 401)
        resp3 = requests.post(self.upload, headers=headers, files=files)
        self.assertEqual(resp3.status_code, 401)
        resp4 = requests.post(self.stream, headers=headers, files=files)
        self.assertEqual(resp4.status_code, 401)
        resp5 = requests.post(self.upload_stream, headers=headers, files=files)
        self.assertEqual(resp5.status_code, 401)
        resp6 = requests.patch(self.upload, headers=headers, files=files)
        self.assertEqual(resp6.status_code, 401)
        resp7 = requests.put(self.upload, headers=headers, files=files)
        self.assertEqual(resp7.status_code, 401)


    def test_E_unauthenticated_request_rejected(self):
        headers = {}
        files = {'file': ('example.csv', open(self.example_csv))}
        resp1 = requests.get(self.list, headers=headers)
        self.assertEqual(resp1.status_code, 400)
        resp2 = requests.get(self.checksum, headers=headers)
        self.assertEqual(resp2.status_code, 400)
        resp3 = requests.post(self.upload, headers=headers, files=files)
        self.assertEqual(resp3.status_code, 400)
        resp4 = requests.post(self.stream, headers=headers, files=files)
        self.assertEqual(resp4.status_code, 400)
        resp5 = requests.post(self.upload_stream, headers=headers, files=files)
        self.assertEqual(resp5.status_code, 400)
        resp6 = requests.patch(self.upload, headers=headers, files=files)
        self.assertEqual(resp6.status_code, 400)
        resp7 = requests.put(self.upload, headers=headers, files=files)
        self.assertEqual(resp7.status_code, 400)


    # uploading files and streams
    #--------------------------


    def test_F_post_file_multi_part_form_data(self):
        newfilename = 'uploaded-example.csv'
        try:
            os.remove(os.path.normpath(self.uploads_folder + '/' + newfilename))
        except OSError:
            pass
        headers = { 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'] }
        files = {'file': (newfilename, open(self.example_csv))}
        resp = requests.post(self.upload, files=files, headers=headers)
        self.assertEqual(resp.status_code, 201)
        uploaded_file = os.path.normpath(self.uploads_folder + '/' + newfilename)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))


    def test_G_patch_file_multi_part_form_data(self):
        newfilename = 'uploaded-example-2.csv'
        try:
            os.remove(os.path.normpath(self.uploads_folder + '/' + newfilename))
        except OSError:
            pass
        headers = { 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'] }
        files = {'file': (newfilename, open(self.example_csv))}
        resp = requests.patch(self.upload, files=files, headers=headers)
        self.assertEqual(resp.status_code, 201)
        uploaded_file = os.path.normpath(self.uploads_folder + '/' + newfilename)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))


    def test_H_put_file_multi_part_form_data(self):
        newfilename = 'uploaded-example-3.csv'
        try:
            os.remove(os.path.normpath(self.uploads_folder + '/' + newfilename))
        except OSError:
            pass
        headers = { 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'] }
        files = {'file': (newfilename, open(self.example_csv))}
        resp = requests.patch(self.upload, files=files, headers=headers)
        uploaded_file = os.path.normpath(self.uploads_folder + '/' + newfilename)
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))
        resp = requests.patch(self.upload, files=files, headers=headers)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))


    def test_I_post_file_to_streaming_endpoint_no_chunked_encoding_data_binary(self):
        newfilename = 'streamed-not-chunked'
        try:
            os.remove(os.path.normpath(self.uploads_folder + '/' + newfilename))
        except OSError:
            pass
        headers = { 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'], 'Filename': newfilename }
        resp = requests.post(self.stream, data=open(self.example_csv), headers=headers)
        self.assertEqual(resp.status_code, 201)
        uploaded_file = os.path.normpath(self.uploads_folder + '/' + newfilename)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))


    def test_J_post_stream_file_chunked_transfer_encoding(self):
        headers = { 'Filename': 'streamed-example.csv', 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'], 'Expect': '100-Continue' }
        resp = requests.post(self.stream, data=lazy_file_reader(self.example_csv), headers=headers)


    def test_K_put_stream_file_chunked_transfer_encoding(self):
        newfilename = 'streamed-put-example.csv'
        try:
            os.remove(os.path.normpath(self.uploads_folder + '/' + newfilename))
        except OSError:
            pass
        headers = { 'Filename': 'streamed-put-example.csv', 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'], 'Expect': '100-Continue' }
        resp = requests.put(self.stream, data=lazy_file_reader(self.example_csv), headers=headers)
        uploaded_file = os.path.normpath(self.uploads_folder + '/' + newfilename)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))
        resp = requests.put(self.stream, data=lazy_file_reader(self.example_csv), headers=headers)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))


    # Metadata
    #---------


    def test_L_get_file_list(self):
        headers = { 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'] }
        resp = requests.get(self.list, headers=headers)
        data = json.loads(resp.text)
        self.assertTrue('uploaded-example.csv' in data.keys())


    def test_M_get_file_checksum(self):
        src = os.path.normpath(self.uploads_folder + '/' + 'uploaded-example.csv')
        headers = { 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'] }
        resp = requests.get(self.base_url + '/checksum?filename=uploaded-example.csv&algorithm=md5', headers=headers)
        data = json.loads(resp.text)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data['checksum'], md5sum(src))
        self.assertEqual(data['algorithm'], 'md5')

    # Informational
    #--------------

    def test_N_head_on_uploads_fails_when_it_should(self):
        resp1 = requests.head(self.upload)
        self.assertEqual(resp1.status_code, 400)
        resp2 = requests.head(self.upload, headers={ 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'] })
        self.assertEqual(resp2.status_code, 400)


    def test_O_head_on_uploads_succeeds_when_conditions_are_met(self):
        files = {'file': ('example.csv', open(self.example_csv))}
        headers={ 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'] }
        resp = requests.head(self.upload, headers=headers, files=files)
        self.assertEqual(resp.status_code, 201)


    def test_P_head_on_stream_fails_when_it_should(self):
        pass


    def test_Q_head_on_stream_succeeds_when_conditions_are_met(self):
        pass

    # Support OPTIONS

    # Space issues

    def test_R_report_informative_error_when_running_out_space(self):
        pass
        # [Errno 28] No space left on device

    # https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
    # make sure alg : none JWT rejected
    # make sure cannot select any other alg

    # JSON data (from nettskjema)
    #----------------------------

    def test_S_create_table(self):
        table_def = self.example_codebook
        headers={ 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'] }
        resp = requests.post(self.base_url + self.test_project + '/rpc/create_table',
                    data=json.dumps(table_def), headers=headers)
        self.assertEqual(resp.status_code, 201)


    def test_T_create_table_is_idempotent(self):
        table_def = self.example_codebook
        headers={ 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'] }
        resp = requests.post(self.base_url + self.test_project + '/rpc/create_table',
                    data=json.dumps(table_def), headers=headers)
        self.assertEqual(resp.status_code, 201)


    def test_U_add_column_codebook(self):
        table_def = self.example_codebook
        table_def['definition']['pages'][0]['elements'].append({
            'elementType': 'QUESTION',
            'questions': [{'externalQuestionId': 'var3'}]
        })
        headers={ 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'] }
        resp = requests.post(self.base_url + self.test_project + '/rpc/create_table',
                    data=json.dumps(table_def), headers=headers)
        self.assertEqual(resp.status_code, 201)


    def test_V_post_data(self):
        data = {'submission_id':1, 'age':93}
        bulk_data = [{'submission_id':4, 'var1':'something', 'var2':'nothing'},
                     {'submission_id':3, 'var1':'sensitive', 'var2': 'kablamo'}]
        headers={ 'Authorization': 'Bearer ' + IMPORT_TOKENS['VALID'] }
        resp1 = requests.post(self.base_url + self.test_project + '/storage/form_63332',
                    data=json.dumps(data), headers=headers)
        resp2 = requests.post(self.base_url + self.test_project + '/storage/form_63332',
                    data=json.dumps(bulk_data), headers=headers)
        self.assertEqual(resp1.status_code, 201)
        self.assertEqual(resp2.status_code, 201)


def main():
    runner = unittest.TextTestRunner()
    suite = []
    suite.append(unittest.TestSuite(map(TestFileApi, [
        'test_A_mangled_valid_token_rejected',
        'test_B_invalid_signature_rejected',
        'test_C_token_with_wrong_role_rejected',
        'test_D_timed_out_token_rejected',
        'test_E_unauthenticated_request_rejected',
        'test_F_post_file_multi_part_form_data',
        'test_G_patch_file_multi_part_form_data',
        'test_H_put_file_multi_part_form_data',
        'test_I_post_file_to_streaming_endpoint_no_chunked_encoding_data_binary',
        'test_J_post_stream_file_chunked_transfer_encoding',
        'test_K_put_stream_file_chunked_transfer_encoding',
        'test_L_get_file_list',
        'test_M_get_file_checksum',
        'test_N_head_on_uploads_fails_when_it_should',
        'test_O_head_on_uploads_succeeds_when_conditions_are_met',
        'test_S_create_table',
        'test_T_create_table_is_idempotent',
        'test_U_add_column_codebook',
        'test_V_post_data',
        ])))
    map(runner.run, suite)


if __name__ == '__main__':
    main()

