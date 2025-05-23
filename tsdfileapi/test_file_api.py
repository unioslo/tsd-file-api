import base64
import json
import logging
import math
import os
import pwd
import random
import shutil
import string
import sys
import tempfile
import time
import unittest
import uuid
from datetime import datetime
from datetime import timedelta
from typing import Optional

import backoff
import libnacl.public
import libnacl.sealed
import libnacl.utils
import requests
from pysquril.backends import PostgresBackend
from tornado.escape import url_escape
from tornado.httpclient import HTTPClient
from tornado.httpclient import HTTPRequest
from tsdapiclient import fileapi

from tsdfileapi.auth import process_access_token
from tsdfileapi.db import postgres_init
from tsdfileapi.resumables import SerialResumable
from tsdfileapi.tokens import gen_test_token_for_user
from tsdfileapi.tokens import gen_test_tokens
from tsdfileapi.tokens import get_test_token_for_p12
from tsdfileapi.utils import find_tenant_storage_path
from tsdfileapi.utils import md5sum
from tsdfileapi.utils import set_mtime
from tsdfileapi.utils import sns_dir

logger = logging.getLogger(__name__)


def project_import_dir(
    config: dict,
    tenant: str,
    *,
    backend: str,
    tenant_pattern: str,
) -> str:
    folder = config["backends"]["disk"][backend]["import_path"].replace(
        tenant_pattern, tenant
    )
    if config.get("create_tenant_dir"):
        if not os.path.lexists(folder):
            print(f"creating {folder}")
            os.makedirs(folder)
    return os.path.normpath(folder)


def lazy_file_reader(filename: str) -> bytes:
    with open(filename, "rb") as f:
        while True:
            data = f.read(10)
            if not data:
                break
            else:
                yield data


@backoff.on_exception(backoff.expo, FileNotFoundError, max_time=0.2)
def await_file(filename: str) -> bool:
    return os.stat(filename) is not None


class TestFileApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            default_port = 3003
            resp = requests.get(f"http://localhost:{default_port}/v1/all/config")
            cls.config = json.loads(resp.text)
        except Exception as e:
            print(e)
            print("Could not load config")
            sys.exit(1)

        # includes p19 - a random project number for integration testing
        cls.test_project = cls.config["test_project"]
        cls.maintenance_url = f"http://localhost:{str(cls.config['port'])}/v1/admin"
        cls.base_url = (
            f"http://localhost:{str(cls.config['port'])}/v1/{cls.test_project}"
        )
        cls.data_folder = cls.config["data_folder"]
        cls.example_csv = os.path.normpath(cls.data_folder + "/example.csv")
        cls.an_empty_file = os.path.normpath(cls.data_folder + "/an-empty-file")
        cls.example_codebook = json.loads(
            open(os.path.normpath(cls.data_folder + "/example-ns.json")).read()
        )
        cls.test_user = cls.config["test_user"]
        cls.test_group = cls.config["test_group"]
        cls.uploads_folder = project_import_dir(
            cls.config,
            cls.config["test_project"],
            backend="files_import",
            tenant_pattern=cls.config["tenant_string_pattern"],
        )
        cls.uploads_folder_p12 = project_import_dir(
            cls.config,
            "p12",
            backend="files_import",
            tenant_pattern=cls.config["tenant_string_pattern"],
        )
        cls.uploads_folder_survey = project_import_dir(
            cls.config,
            cls.config["test_project"],
            backend="survey",
            tenant_pattern=cls.config["tenant_string_pattern"],
        )
        cls.test_sns_url = "/v1/{}/sns/{}/{}".format(
            cls.config["test_project"],
            cls.config["test_keyid"],
            cls.config["test_formid"],
        )
        cls.test_sns_dir = cls.config["backends"]["disk"]["sns"]["import_path"]
        cls.test_formid = cls.config["test_formid"]
        cls.test_keyid = cls.config["test_keyid"]

        class Options:
            tenant_storage_cache = {}

        cls.sns_uploads_folder = sns_dir(
            cls.test_sns_dir,
            cls.config["test_project"],
            cls.test_sns_url,
            cls.config["tenant_string_pattern"],
            test=True,
            options=Options(),
        )
        cls.publication_import_folder = cls.config["backends"]["disk"]["publication"][
            "import_path"
        ].replace("pXX", cls.config["test_project"])
        cls.apps_import_folder = cls.config["backends"]["disk"]["apps_files"][
            "import_path"
        ].replace("pXX", cls.config["test_project"])
        cls.verbose = cls.config.get("verbose")

        # endpoints
        cls.upload = cls.base_url + "/files/upload"
        cls.sns_upload = (
            cls.base_url
            + "/sns/"
            + cls.config["test_keyid"]
            + "/"
            + cls.config["test_formid"]
        )
        cls.upload_sns_wrong = (
            cls.base_url + "/sns/" + "WRONG" + "/" + cls.config["test_formid"]
        )
        cls.stream = cls.base_url + "/files/stream"

        cls.export = cls.base_url + "/files/export"
        cls.resumables = cls.base_url + "/files/resumables"
        cls.publication_import = cls.base_url + "/publication/import"
        cls.publication_export = cls.base_url + "/publication/export"
        cls.publication_tables = cls.base_url + "/publication/tables"
        cls.survey = cls.base_url + "/survey"
        cls.apps = cls.base_url + "/apps"
        cls.logs = cls.base_url + "/logs"
        cls.test_project = cls.test_project
        cls.tenant_string_pattern = cls.config["tenant_string_pattern"]

        # auth tokens
        global TEST_TOKENS
        TEST_TOKENS = gen_test_tokens(cls.config)
        global P12_TOKEN
        P12_TOKEN = get_test_token_for_p12(cls.config)

        # resumables
        cls.resume_file1 = os.path.normpath(cls.data_folder + "/resume-file1")
        cls.resume_file2 = os.path.normpath(cls.data_folder + "/resume-file2")
        # filename tests
        cls.so_sweet = os.path.normpath(cls.data_folder + "/så_søt(1).txt")
        cls.red = os.path.normpath(cls.data_folder + "/rød_fil_(1).txt")
        cls.this_is_a_file = os.path.normpath(cls.data_folder + "/this is a file")
        cls.test_upload_id = "96c68dad-8dc5-4076-9569-92394001d42a"
        # TODO: make this configurable
        # do not dist with package
        cls.large_file = os.path.normpath(cls.data_folder + "/large-file")

    @classmethod
    def tearDownClass(cls):
        uploaded_files = os.listdir(cls.uploads_folder)
        test_files = os.listdir(cls.config["data_folder"])
        today = datetime.fromtimestamp(time.time()).isoformat()[:10]
        file_list = [
            "streamed-example.csv",
            "uploaded-example.csv",
            "uploaded-example-2.csv",
            "uploaded-example-3.csv",
            "streamed-not-chunked",
            "streamed-put-example.csv",
        ]
        for _file in uploaded_files:
            # TODO: eventually remove - still want to inspect them
            # manually while the data pipelines are in alpha
            if _file in [
                "totar",
                "totar2",
                "decrypted-aes.csv",
                "totar3",
                "totar4",
                "ungz1",
                "ungz-aes1",
                "uploaded-example-2.csv",
                "uploaded-example-3.csv",
            ]:
                continue
            if (_file in test_files) or (today in _file) or (_file in file_list):
                try:
                    os.remove(os.path.normpath(cls.uploads_folder + "/" + _file))
                except OSError as e:
                    logger.error(e)
                    continue

    # Import Auth
    # ------------

    def test_D_timed_out_token_rejected(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["TIMED_OUT"]}
        resp = requests.put(self.stream, headers=headers)
        self.assertEqual(resp.status_code, 403)
        resp = requests.patch(self.stream, headers=headers)
        self.assertEqual(resp.status_code, 403)

    def test_E_unauthenticated_request_rejected(self) -> None:
        headers = {}
        resp = requests.put(self.stream, headers=headers)
        self.assertEqual(resp.status_code, 403)
        resp = requests.patch(self.stream, headers=headers)
        self.assertEqual(resp.status_code, 403)

    # uploading files and streams
    # ----------------------------

    # multipart formdata endpoint

    def remove(self, target_uploads_folder: str, newfilename: str) -> None:
        try:
            _file = os.path.normpath(target_uploads_folder + "/" + newfilename)
            os.remove(_file)
        except OSError:
            pass

    def mp_fd(
        self,
        newfilename: str,
        target_uploads_folder: str,
        url: str,
        method: str,
    ) -> requests.Response:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        f = open(self.example_csv)
        files = {"file": (newfilename, f)}
        if method == "PUT":
            # not going to remove, need to check that it is idempotent
            resp = requests.put(url, files=files, headers=headers)
        f.close()
        return resp

    def check_copied_sns_file_exists(self, filename: str) -> None:
        file = self.sns_uploads_folder + "/" + filename
        hidden_file = file.replace(
            self.config["public_key_id"], ".tsd/" + self.config["public_key_id"]
        )
        self.assertTrue(os.path.lexists(hidden_file))

    def t_put_mp(self, uploads_folder: str, newfilename: str, url: str) -> None:
        target = os.path.normpath(uploads_folder + "/" + newfilename)
        # remove file from previous round
        self.remove(uploads_folder, newfilename)
        # req1
        resp = self.mp_fd(newfilename, target, url, "PUT")
        uploaded_file = os.path.normpath(uploads_folder + "/" + newfilename)
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(await_file(uploaded_file))
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))
        # req2
        resp2 = self.mp_fd(newfilename, target, url, "PUT")
        self.assertEqual(resp2.status_code, 201)
        self.assertTrue(await_file(uploaded_file))
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))

    def test_H1_put_file_multi_part_form_data_sns(self) -> None:
        filename = "sns-uploaded-example-3.csv"
        self.t_put_mp(self.sns_uploads_folder, filename, self.sns_upload)
        self.check_copied_sns_file_exists(filename)

    def test_H5XX_when_no_keydir_exists(self) -> None:
        newfilename = "new1"
        target = os.path.normpath(self.sns_uploads_folder + "/" + newfilename)
        resp1 = self.mp_fd(newfilename, target, self.upload_sns_wrong, "PUT")
        self.assertEqual(resp1.status_code, 500)

    # streaming endpoint

    def test_I_put_file_to_streaming_endpoint_no_chunked_encoding_data_binary(
        self,
    ) -> None:
        newfilename = "streamed-not-chunked"
        uploaded_file = os.path.normpath(
            self.uploads_folder + "/" + self.test_group + "/" + newfilename
        )
        try:
            os.remove(uploaded_file)
        except OSError:
            pass
        headers = {
            "Authorization": "Bearer " + TEST_TOKENS["VALID"],
            "Filename": newfilename,
        }
        resp = requests.put(self.stream, data=open(self.example_csv), headers=headers)
        self.assertEqual(resp.status_code, 201)

        self.assertTrue(await_file(uploaded_file))
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))

    def test_K_put_stream_file_chunked_transfer_encoding(self) -> None:
        newfilename = "streamed-put-example.csv"
        uploaded_file = os.path.normpath(
            self.uploads_folder + "/" + self.test_group + "/" + newfilename
        )
        try:
            os.remove(uploaded_file)
        except OSError:
            pass
        headers = {
            "Filename": "streamed-put-example.csv",
            "Authorization": "Bearer " + TEST_TOKENS["VALID"],
            "Expect": "100-Continue",
        }
        resp = requests.put(
            self.stream, data=lazy_file_reader(self.example_csv), headers=headers
        )
        self.assertTrue(await_file(uploaded_file))
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))
        resp = requests.put(
            self.stream, data=lazy_file_reader(self.example_csv), headers=headers
        )
        self.assertTrue(await_file(uploaded_file))
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))
        self.assertEqual(resp.status_code, 201)

    # Informational
    # --------------

    def use_generic_table(self, app_route: str, url_tokens_method: str) -> None:
        methods = {"GET": requests.get, "PUT": requests.put, "DELETE": requests.delete}
        for url, token, method in url_tokens_method:
            headers = {"Authorization": "Bearer " + TEST_TOKENS[token]}
            full_url = self.base_url + app_route + url
            resp = methods[method](full_url, headers=headers)
            self.assertTrue(resp.status_code in [200, 201])

    def test_tables(self) -> None:
        headers = {"Authorization": f"Bearer {TEST_TOKENS['EXPORT']}"}

        # if it exists
        resp = requests.delete(
            f"{self.base_url}/apps/generic/tables/table1",
            headers=headers,
        )
        resp = requests.delete(
            f"{self.base_url}/apps/generic/tables/table2",
            headers=headers,
        )

        # create  a table
        data = {"x": 10, "y": 11}
        resp = requests.put(
            f"{self.base_url}/apps/generic/tables/table1",
            data=json.dumps(data),
            headers=headers,
        )
        resp = requests.get(
            f"{self.base_url}/apps/generic/tables/table1",
            headers=headers,
        )
        self.assertEqual(json.loads(resp.text), [data])

        # rename the table
        resp = requests.post(
            f"{self.base_url}/apps/generic/tables/table1?alter=name=eq.table2",
            headers=headers,
        )
        self.assertEqual(json.loads(resp.text), {"tables": ["table1"]})

        resp = requests.get(
            f"{self.base_url}/apps/generic/tables/table2",
            headers=headers,
        )
        self.assertEqual(json.loads(resp.text), [data])

        resp = requests.get(
            f"{self.base_url}/apps/generic/tables/table1",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 404)

    def test_XXX_query_invalid(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        resp = requests.get(
            f"{self.base_url}/survey/user_number/submissions?select=count(*)",
            headers=headers,
        )
        # Proper test for not exists table
        self.assertEqual(resp.status_code, 404)
        # Do not throw non exist at audit
        resp = requests.get(
            f"{self.base_url}/survey/user_number/audit?select=count(*)",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, "[]")

    def test_XXX_nettskjema_backend(self) -> None:
        data = [
            {"key1": 7, "key2": "bla", "id": random.randint(0, 1000000)},
            {"key1": 99, "key3": False, "id": random.randint(0, 1000000)},
        ]
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}

        resp = requests.delete(f"{self.survey}/123456/submissions", headers=headers)
        resp = requests.delete(f"{self.survey}/56789/submissions", headers=headers)

        # add data to tables
        resp = requests.put(
            f"{self.base_url}/survey/123456/submissions",
            data=json.dumps(data),
            headers=headers,
        )
        resp = requests.put(
            f"{self.base_url}/survey/56789/submissions",
            data=json.dumps(data),
            headers=headers,
        )
        # get it back
        resp = requests.get(f"{self.survey}/123456/submissions", headers=headers)
        resp_data = json.loads(resp.text)
        self.assertEqual(data, resp_data)
        self.assertEqual(len(resp_data), 2, "wrong number of submissions")
        self.assertEqual(resp_data[0].get("key1"), 7)
        self.assertEqual(resp_data[1].get("key1"), 99)
        self.assertEqual(resp.status_code, 200)
        # audit functionality
        resp = requests.patch(
            f"{self.survey}/123456/submissions?set=key1&where=key2=eq.bla",
            headers=headers,
            data=json.dumps({"key1": 5}),
        )
        self.assertEqual(resp.status_code, 201)
        # that the update propagated
        resp = requests.get(
            f"{self.survey}/123456/submissions?order=key1.asc", headers=headers
        )
        data = json.loads(resp.text)
        self.assertEqual(data[0].get("key1"), 5)
        # that we recorded the change in the audit
        resp = requests.get(f"{self.survey}/123456/audit", headers=headers)
        data = json.loads(resp.text)
        self.assertTrue(data)
        self.assertEqual(data[-1].get("diff"), {"key1": 5})
        self.assertEqual(data[-1].get("previous").get("key1"), 7)
        self.assertEqual(resp.status_code, 200)
        resp = requests.delete(f"{self.survey}/123456/audit", headers=headers)
        self.assertEqual(resp.status_code, 200)
        # metadata functionality
        resp = requests.put(
            f"{self.base_url}/survey/123456/metadata",
            data=json.dumps({"my": "metadata"}),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(f"{self.base_url}/survey/123456/metadata", headers=headers)
        data = json.loads(resp.text)
        self.assertEqual(data[0], {"my": "metadata"})
        self.assertEqual(resp.status_code, 200)
        resp = requests.delete(
            f"{self.base_url}/survey/123456/metadata", headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        # check endpoint overview
        resp = requests.get(f"{self.base_url}/survey", headers=headers)
        data = json.loads(resp.text)
        self.assertTrue("123456" in data["tables"])
        self.assertEqual(resp.status_code, 200)
        # get data
        resp = requests.get(f"{self.base_url}/survey/123456", headers=headers)
        data = json.loads(resp.text)
        self.assertTrue("metadata" in data["data"])
        self.assertTrue("submissions" in data["data"])
        self.assertTrue("attachments" in data["data"])

        # perform some queries
        resp = requests.get(
            f"{self.base_url}/survey/123456/submissions?select=count(*)",
            headers=headers,
        )
        data = json.loads(resp.text)
        self.assertEqual(data[0][0], 2)
        resp = requests.get(
            f"{self.base_url}/survey/*/submissions?select=count(*)", headers=headers
        )
        data = json.loads(resp.text)
        self.assertEqual(len(data), 2, f"unexpected number of tables: {data}")
        for entry in data:
            for formid, num_submmissions in entry.items():
                self.assertEqual(num_submmissions, [2])
        nettskjema_url_tokens_method = [
            ("/123456/submissions", "ADMIN", "GET"),
            (
                "/123456/submissions?select=key1&where=key2=eq.bla&order=key1.desc",
                "ADMIN",
                "GET",
            ),
            ("/123456/submissions", "ADMIN", "GET"),
            ("/123456/submissions?where=key1=eq.99", "ADMIN", "DELETE"),
            ("/123456/submissions", "ADMIN", "GET"),
            ("/123456/submissions?where=key1=not.is.null", "ADMIN", "DELETE"),
        ]
        for app, acl in [("/survey", nettskjema_url_tokens_method)]:
            self.use_generic_table(app, acl)

        resp = requests.delete(
            f"{self.base_url}/survey/56789/submissions", headers=headers
        )
        self.assertEqual(resp.status_code, 200)

        resp = requests.delete(f"{self.survey}/123456/submissions", headers=headers)
        self.assertEqual(resp.status_code, 200)

        resp = requests.get(
            f"{self.base_url}/survey/56789/submissions", headers=headers
        )
        self.assertEqual(resp.status_code, 404)

        # attachments
        file = url_escape("some-survey-attachment.txt")
        resp = requests.put(
            f"{self.survey}/123456/attachments/{file}",
            data=lazy_file_reader(self.so_sweet),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)

        resp = requests.get(f"{self.survey}/123456/attachments/{file}", headers=headers)
        self.assertEqual(resp.status_code, 200)

        resp = requests.delete(
            f"{self.survey}/123456/attachments/{file}", headers=headers
        )
        self.assertEqual(resp.status_code, 200)

        # check the backup
        resp = requests.get(
            f"{self.survey}/123456/backup/attachments/{file}", headers=headers
        )
        self.assertEqual(resp.status_code, 200)

        # restore the specific attachment
        resp = requests.post(
            f"{self.survey}/123456/backup/attachments/{file}?restore",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.text), {"restores": [file]})
        resp = requests.get(
            f"{self.survey}/123456/backup/attachments/{file}", headers=headers
        )
        self.assertEqual(resp.status_code, 404)
        resp = requests.get(f"{self.survey}/123456/attachments/{file}", headers=headers)
        self.assertEqual(resp.status_code, 200)

        resp = requests.put(
            f"{self.survey}/123456/attachments/another-amazing-file.json",
            data=lazy_file_reader(self.so_sweet),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)

        resp = requests.delete(f"{self.survey}/123456/attachments", headers=headers)
        self.assertEqual(resp.status_code, 200)

        resp = requests.get(f"{self.survey}/123456/attachments", headers=headers)
        self.assertEqual(resp.status_code, 404)

        # check the backup
        resp = requests.get(f"{self.survey}/123456/backup/attachments", headers=headers)
        self.assertEqual(resp.status_code, 200)
        file_list = map(lambda x: x.get("filename"), json.loads(resp.text).get("files"))
        self.assertTrue("another-amazing-file.json" in file_list)

        # manipulate the mtime of the backed up folder, to fall outside retention period
        survey_disk_config = self.config.get("backends").get("disk").get("survey")
        survey_path = survey_disk_config.get("import_path")
        retention_period = survey_disk_config.get("backup_deletes", {}).get(
            "backup_days", 90
        )
        new_mtime = int(
            (datetime.now() - timedelta(days=retention_period + 1)).timestamp()
        )
        target = f"{survey_path}/123456/backup/attachments".replace(
            self.config.get("tenant_string_pattern"),
            self.config.get("test_project"),
        )
        set_mtime(target, new_mtime)
        resp = requests.get(f"{self.survey}/123456/backup/attachments", headers=headers)
        self.assertEqual(resp.status_code, 404)  # not available anymore

        # try to restore resource that is outside retention period
        resp = requests.post(
            f"{self.survey}/123456/backup/attachments?restore",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 404)

        # reset mtime
        set_mtime(target, int(time.time()))

        # now restore all deleted attachments
        resp = requests.post(
            f"{self.survey}/123456/backup/attachments?restore",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(f"{self.survey}/123456/attachments/{file}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(
            f"{self.survey}/123456/attachments/another-amazing-file.json",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

        # delete them again
        resp = requests.delete(f"{self.survey}/123456/attachments", headers=headers)
        self.assertEqual(resp.status_code, 200)

        # delete the backups
        resp = requests.delete(
            f"{self.survey}/123456/backup/attachments", headers=headers
        )
        self.assertEqual(resp.status_code, 200)

        # tasks
        # definitions
        resp = requests.put(
            f"{self.survey}/123456/tasks/definitions",
            data=json.dumps({"definition": "this is a task"}),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(
            f"{self.survey}/123456/tasks/definitions",
            headers=headers,
        )
        self.assertEqual(json.loads(resp.text), [{"definition": "this is a task"}])
        resp = requests.delete(
            f"{self.survey}/123456/tasks/definitions",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

        # deliveries
        resp = requests.put(
            f"{self.survey}/123456/tasks/deliveries",
            data=json.dumps({"task_id": "lol", "task_data": "meh"}),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(
            f"{self.survey}/123456/tasks/deliveries",
            headers=headers,
        )
        self.assertEqual(
            json.loads(resp.text), [{"task_id": "lol", "task_data": "meh"}]
        )
        resp = requests.delete(
            f"{self.survey}/123456/tasks/deliveries",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

        # config
        resp = requests.put(
            f"{self.survey}/config",
            data=json.dumps({"something": "my app needs this data"}),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(
            f"{self.survey}/config",
            headers=headers,
        )
        self.assertEqual(
            json.loads(resp.text), [{"something": "my app needs this data"}]
        )
        resp = requests.delete(
            f"{self.survey}/config",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

        # schema
        resp = requests.put(
            f"{self.survey}/schemas/submissions",
            data=json.dumps({"schema": {"var": "str"}}),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(
            f"{self.survey}/schemas/submissions",
            headers=headers,
        )
        self.assertEqual(json.loads(resp.text), [{"schema": {"var": "str"}}])
        resp = requests.delete(
            f"{self.survey}/schemas/submissions",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

        ### restoring edited and deleted submission data

        sub1 = {"answers": {"pk": 0, "x": 4, "y": 0}, "metadata": {"such": "meta"}}
        sub2 = {"answers": {"pk": 1, "x": 9, "y": 8}, "metadata": {"such": "wow"}}
        submissions = [sub1, sub2]
        formid = "8865852"
        resp = requests.put(
            f"{self.base_url}/survey/{formid}/submissions",
            data=json.dumps(submissions),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)

        # make an edit, and delete
        resp = requests.patch(
            f"{self.base_url}/survey/{formid}/submissions?set=answers&where=answers.pk=eq.0",
            data=json.dumps({"answers": {"pk": 0, "x": 5, "y": 1}}),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.delete(
            f"{self.base_url}/survey/{formid}/submissions",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

        # restore to original state
        resp = requests.post(
            f"{self.base_url}/survey/{formid}/audit?restore&primary_key=answers.pk",
            headers=headers,
        )
        self.assertTrue((len(json.loads(resp.text).get("restores")), 2))

        # correct amount of events
        resp = requests.get(
            f"{self.base_url}/survey/{formid}/submissions",
            headers=headers,
        )
        self.assertTrue(len(json.loads(resp.text)), 2)

        # check contents match originals
        resp = requests.get(
            f"{self.base_url}/survey/{formid}/submissions?where=answers.pk=eq.0",
            headers=headers,
        )
        self.assertEqual(json.loads(resp.text)[0], sub1)
        resp = requests.get(
            f"{self.base_url}/survey/{formid}/submissions?where=answers.pk=eq.1",
            headers=headers,
        )
        self.assertEqual(json.loads(resp.text)[0], sub2)

        # cleanup
        resp = requests.delete(
            f"{self.base_url}/survey/{formid}/submissions",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.delete(
            f"{self.base_url}/survey/{formid}/audit",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(
            f"{self.base_url}/survey/{formid}/audit",
            headers=headers,
        )
        self.assertEqual(json.loads(resp.text), [])

        # edit-only restore
        sub1 = {"answers": {"pk": 0, "x": 4, "y": 0}, "metadata": {"such": "meta"}}
        sub2 = {"answers": {"pk": 1, "x": 9, "y": 8}, "metadata": {"such": "wow"}}
        submissions = [sub1, sub2]
        formid = "8083601"
        resp = requests.put(
            f"{self.base_url}/survey/{formid}/submissions",
            data=json.dumps(submissions),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)

        # make an edit
        resp = requests.patch(
            f"{self.base_url}/survey/{formid}/submissions?set=answers&where=answers.pk=eq.0",
            data=json.dumps({"answers": {"pk": 0, "x": 999}}),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.post(
            f"{self.base_url}/survey/{formid}/audit?restore&primary_key=answers.pk",
            headers=headers,
        )
        self.assertTrue((len(json.loads(resp.text).get("updates")), 1))
        # cleanup
        resp = requests.delete(
            f"{self.base_url}/survey/{formid}/submissions",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.delete(
            f"{self.base_url}/survey/{formid}/audit",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

    def test_survey_api_queries(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}

        # add data
        sub1 = {
            "answers": {"pk": 0, "x": 4, "y": 0, "z": "meh"},
            "metadata": {"food": "sisselrot"},
        }
        sub2 = {
            "answers": {"pk": 1, "x": 9, "y": 8, "z": ":), :|, :("},
            "metadata": {"food": "strutseving"},
        }
        meta = {
            "answers": {"pk": "int", "x": "int", "y": "int"},
            "metadata": {"food": "str"},
        }
        submissions = [sub1, sub2]

        formid = "11223344"
        resp = requests.put(
            f"{self.base_url}/survey/{formid}/submissions",
            data=json.dumps(submissions),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.put(
            f"{self.base_url}/survey/{formid}/metadata",
            data=json.dumps(meta),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)

        formid = "55667788"
        resp = requests.put(
            f"{self.base_url}/survey/{formid}/submissions",
            data=json.dumps(submissions),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.put(
            f"{self.base_url}/survey/{formid}/metadata",
            data=json.dumps(meta),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)

        formid = "11999999"
        resp = requests.put(
            f"{self.base_url}/survey/{formid}/submissions",
            data=json.dumps(submissions),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.put(
            f"{self.base_url}/survey/{formid}/metadata",
            data=json.dumps(meta),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)

        # fuzzy matching, aggregate
        resp = requests.get(
            f"{self.base_url}/survey/11*/submissions?select=count(*)",
            headers=headers,
        )
        out = json.loads(resp.text)
        self.assertEqual(len(out), 2)
        for entry in out:
            for k in ["11223344", "11999999"]:
                num = entry.get(k)
                if num:
                    self.assertEqual(num, [2])

        # fuzzy matching, non aggregate
        resp = requests.get(
            f"{self.base_url}/survey/11*/submissions?where=metadata.food=eq.sisselrot",
            headers=headers,
        )
        out = json.loads(resp.text)
        self.assertEqual(len(out), 2)
        for entry in out:
            for k, v in entry.items():
                self.assertTrue(k in ["11223344", "11999999"])
                self.assertTrue(len(v) == 1)

        resp = requests.get(
            f"{self.base_url}/survey/*/metadata",
            headers=headers,
        )
        out = json.loads(resp.text)
        self.assertEqual(len(out), 3)

        # quoting
        resp = requests.get(
            f"{self.base_url}/survey/11223344/submissions?select=answers.x&where=answers.z=eq.':), :|, :('",
            headers=headers,
        )
        out = json.loads(resp.text)
        self.assertEqual(out, [[9]])

        # set to null
        resp = requests.patch(
            f"{self.base_url}/survey/11223344/submissions?set=answers&where=answers.z=eq.meh",
            headers=headers,
            data=json.dumps({"answers": None}),
        )
        resp = requests.get(
            f"{self.base_url}/survey/11223344/submissions?where=metadata.food=eq.sisselrot",
            headers=headers,
        )
        out = json.loads(resp.text)
        self.assertEqual(out[0].get("answers"), None)

        # cleanup
        for formid in ["11223344", "11999999", "55667788"]:
            requests.delete(
                f"{self.base_url}/survey/{formid}/submissions",
                headers=headers,
            )
            requests.delete(
                f"{self.base_url}/survey/{formid}/metadata",
                headers=headers,
            )
            requests.delete(
                f"{self.base_url}/survey/{formid}/audit",
                headers=headers,
            )

    def test_XXX_load(self) -> None:
        numrows = 250000  # responses per survey
        numkeys = 1500  # questions per survey

        print("generating test data")
        pool = postgres_init(self.config["backends"]["postgres"]["dbconfig"])
        db = PostgresBackend(pool, schema="p11")
        for i in range(numrows):
            row = {}
            for j in range(numkeys):
                key = f"k{j}"
                row[key] = j
            uid = str(uuid.uuid4())
            row["id"] = uid
            # insert row
            db.table_insert("loadtest", row)
            total = i
            if i % (numrows / 10.0) == 0:
                print(f"{total} rows generated")
                total += total

        # sqlite findings:
        # ~ 10gb of data in sqlite
        # on localhost, fetching everything:
        # real 0m48.339s
        # in a json file, that is 4.7gb

        # postgres findings:
        # on localhost, fetching everything:
        # real    4m21.898s
        # CPU intensive, memory fine

    # More Authn+z
    # ------------

    def test_Y_invalid_project_number_rejected(self) -> None:
        data = {"submission_id": 11, "age": 193}
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        resp = requests.put(
            "http://localhost:"
            + str(self.config["port"])
            + "/p12-2193-1349213*&^/tables/generic/form_63332",
            data=json.dumps(data),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 404)

    def test_Z_token_for_other_project_rejected(self) -> None:
        data = {"submission_id": 11, "age": 193}
        headers = {"Authorization": "Bearer " + TEST_TOKENS["WRONG_PROJECT"]}
        resp = requests.put(
            self.base_url + "/survey/63332/submissions",
            data=json.dumps(data),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 403)

    def test_ZA_choosing_file_upload_directories_based_on_tenant_works(self) -> None:
        newfilename2 = "streamed-put-example-p12.csv"
        try:
            os.remove(
                os.path.normpath(
                    self.uploads_folder_p12 + "/p12-member-group/" + newfilename2
                )
            )
        except OSError:
            pass
        headers2 = {
            "Filename": "streamed-put-example-p12.csv",
            "Authorization": "Bearer " + P12_TOKEN,
            "Expect": "100-Continue",
        }
        resp2 = requests.put(
            "http://localhost:" + str(self.config["port"]) + "/v1/p12/files/stream",
            data=lazy_file_reader(self.example_csv),
            headers=headers2,
        )
        self.assertEqual(resp2.status_code, 201)
        uploaded_file2 = os.path.normpath(
            self.uploads_folder_p12 + "/p12-member-group/" + newfilename2
        )
        self.assertTrue(await_file(uploaded_file2))
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file2))

    def test_ZB_sns_folder_logic_is_correct(self) -> None:
        class Options:
            tenant_storage_cache = {}

        # lowercase in key id
        self.assertRaises(
            Exception,
            sns_dir,
            self.test_sns_dir,
            "p11",
            "/v1/p11/sns/255cE5ED50A7558B/98765",
            self.tenant_string_pattern,
            options=Options(),
        )
        # too long but still valid key id
        self.assertRaises(
            Exception,
            sns_dir,
            self.test_sns_dir,
            "p11",
            "/v1/p11/sns/255CE5ED50A7558BXIJIJ87878/98765",
            self.tenant_string_pattern,
            options=Options(),
        )
        # non-numeric formid
        self.assertRaises(
            Exception,
            sns_dir,
            self.test_sns_dir,
            "p11",
            "255CE5ED50A7558B",
            "99999-%$%&*",
            self.tenant_string_pattern,
            options=Options(),
        )

    def test_ZC_setting_ownership_based_on_user_works(self) -> None:
        token = gen_test_token_for_user(self.config, self.test_user)
        headers = {
            "Authorization": "Bearer " + token,
            "Filename": "testing-chowner.txt",
        }
        requests.put(
            self.stream, data=lazy_file_reader(self.example_gz_aes), headers=headers
        )
        intended_owner = pwd.getpwnam(self.test_user).pw_uid
        effective_owner = os.stat(
            self.uploads_folder + "/" + self.test_group + "/testing-chowner.txt"
        ).st_uid
        self.assertEqual(intended_owner, effective_owner)

    def test_ZD_cannot_upload_empty_file_to_sns(self) -> None:
        files = {"file": ("an-empty-file", open(self.an_empty_file))}
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        resp = requests.put(self.sns_upload, files=files, headers=headers)
        self.assertEqual(resp.status_code, 400)

    # client-side specification of groups

    def test_ZE_stream_works_with_client_specified_group(self) -> None:
        headers = {
            "Authorization": "Bearer " + TEST_TOKENS["VALID"],
            "Expect": "100-Continue",
        }
        url = (
            self.stream + "/streamed-example-with-group-spec.csv?group=p11-member-group"
        )
        resp = requests.put(
            url, data=lazy_file_reader(self.example_csv), headers=headers
        )
        self.assertEqual(resp.status_code, 201)

    # export

    def test_ZJ_export_file_restrictions_enforced(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["EXPORT"]}
        for name in [
            "/bin/bash -c",
            "!#/bin/bash",
            "!@#$%^&*()-+",
            "../../../p01/data/durable",
        ]:
            resp = requests.get(self.export + "/" + name, headers=headers)
            self.assertTrue(resp.status_code in [403, 404, 401])

    def test_ZK_export_list_dir_works(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["EXPORT"]}
        resp = requests.get(self.export, headers=headers)
        data = json.loads(resp.text)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(data["files"]), 3)
        self.assertTrue(len(data["files"][0].keys()), 3)

    def test_ZL_export_file_works(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["ADMIN"]}
        resp = requests.get(self.export + "/file1", headers=headers)
        self.assertEqual(resp.text, "some data\n")
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(
            self.export + "/" + url_escape("blå_fil_3_(v1).txt"), headers=headers
        )
        self.assertEqual(resp.text, "even more data\n")
        self.assertEqual(resp.status_code, 200)
        resp = requests.head(
            self.export + "/" + url_escape("this is a file"), headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(
            self.export + "/" + url_escape("this is a file"), headers=headers
        )
        self.assertEqual(resp.text, "Lol\n")
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(
            self.export + "/" + url_escape("this+is+another+file"), headers=headers
        )
        self.assertEqual(resp.text, "epiphenomena\n")
        self.assertEqual(resp.status_code, 200)

    # resumable uploads

    def resource_name(
        self, filepath: str, is_dir: bool, remote_resource_key: str, group: str
    ) -> str:
        if not is_dir:
            return os.path.basename(filepath)
        elif is_dir and not remote_resource_key:
            return f"{group}/{filepath[1:]}"  # strip leading /
        elif is_dir and remote_resource_key:
            return f"{group}/{remote_resource_key}/{os.path.basename(filepath)}"

    def start_new_resumable(
        self,
        filepath: str,
        chunksize: int = 1,
        large_file: bool = False,
        stop_at: int = None,
        token: str = None,
        endpoint: str = None,
        uploads_folder: str = None,
        is_dir: bool = None,
        remote_resource_key: str = None,
        group: str = None,
        public_key: Optional[libnacl.public.PublicKey] = None,
    ) -> None:
        if not token:
            token = TEST_TOKENS["VALID"]
        if not endpoint:
            endpoint = self.stream
        url = "{}/{}".format(
            endpoint, self.resource_name(filepath, is_dir, remote_resource_key, group)
        )
        env = ""
        resp = fileapi.initiate_resumable(
            env,
            self.test_project,
            filepath,
            token,
            chunksize=chunksize,
            new=True,
            group=group,
            verify=False,
            dev_url=url,
            stop_at=stop_at,
            public_key=public_key,
        ).get("response")
        if stop_at:
            return resp["id"]
        self.assertEqual(resp["max_chunk"], "end")
        self.assertTrue(resp["id"] is not None)
        self.assertEqual(resp["filename"], os.path.basename(filepath))
        if not large_file:
            if not uploads_folder:
                uploads_folder = self.uploads_folder + "/" + self.test_group
            remote_resource = uploads_folder + "/" + os.path.basename(filepath)
            self.assertTrue(await_file(remote_resource))
            self.assertEqual(md5sum(filepath), md5sum(remote_resource))

    def test_ZM_resume_new_upload_works_is_idempotent(self) -> None:
        self.start_new_resumable(self.resume_file1, chunksize=5)

    def test_ZM2_resume_upload_with_directory(self) -> None:
        group = f"{self.test_project}-member-group"
        remote_resource_key = "testing123"
        self.start_new_resumable(
            self.resume_file1,
            chunksize=5,
            group=group,
            is_dir=True,
            remote_resource_key=remote_resource_key,
            uploads_folder="/".join([self.uploads_folder, group, remote_resource_key]),
        )
        # create two resumables with the same filename but different keys
        top_level_dir = "top"
        sub_dir = f"{top_level_dir}/sub"
        top_id = self.start_new_resumable(
            self.resume_file1,
            chunksize=5,
            group=group,
            is_dir=True,
            remote_resource_key=top_level_dir,
            uploads_folder="/".join([self.uploads_folder, group, top_level_dir]),
            stop_at=2,
        )
        sub_id = self.start_new_resumable(
            self.resume_file1,
            chunksize=5,
            group=group,
            is_dir=True,
            remote_resource_key=sub_dir,
            uploads_folder="/".join([self.uploads_folder, group, sub_dir]),
            stop_at=3,
        )
        # get_resumable: finds the correct resumable based on filename and key
        from urllib.parse import quote

        target = os.path.basename(self.resume_file1)
        url = f"{self.resumables}/{target}?key={quote(top_level_dir, safe='')}"
        env = ""  # not used when passing url
        resp = fileapi.get_resumable(
            env,
            self.test_project,
            TEST_TOKENS["VALID"],
            dev_url=url,
        ).get("overview")
        self.assertEqual(resp["id"], top_id)
        url = f"{self.resumables}/{target}?key={quote(sub_dir, safe='')}"
        resp = fileapi.get_resumable(
            env,
            self.test_project,
            TEST_TOKENS["VALID"],
            dev_url=url,
        ).get("overview")
        self.assertEqual(resp["id"], sub_id)

    def test_ZN_resume_works_with_upload_id_match(self) -> None:
        cs = 5
        proj = ""
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id = self.start_new_resumable(filepath, chunksize=cs, stop_at=1)
        token = TEST_TOKENS["VALID"]
        url = f"{self.resumables}/{filename}"
        print("---> going to resume from chunk 2:")
        resp = fileapi.initiate_resumable(
            proj,
            self.test_project,
            filepath,
            token,
            chunksize=cs,
            new=False,
            group=None,
            verify=True,
            upload_id=upload_id,
            dev_url=url,
        ).get("response")
        self.assertEqual(resp["max_chunk"], "end")
        self.assertTrue(resp["id"] is not None)
        self.assertEqual(resp["filename"], filename)
        self.assertTrue("key" in resp.keys())

    def test_ZO_resume_works_with_filename_match(self) -> None:
        print("test_ZO_resume_works_with_filename_match")
        cs = 5
        proj = ""
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id = self.start_new_resumable(filepath, chunksize=cs, stop_at=1)
        token = TEST_TOKENS["VALID"]
        url = f"{self.resumables}/{filename}"
        print("---> going to resume from chunk 2:")
        resp = fileapi.initiate_resumable(
            proj,
            self.test_project,
            filepath,
            token,
            chunksize=cs,
            new=False,
            group=None,
            verify=True,
            upload_id=upload_id,
            dev_url=url,
        ).get("response")
        self.assertEqual(resp["max_chunk"], "end")
        self.assertTrue(resp["id"] is not None)
        self.assertEqual(resp["filename"], filename)

    def test_ZP_resume_do_not_upload_if_md5_mismatch(self) -> None:
        cs = 5
        proj = ""
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id = self.start_new_resumable(filepath, chunksize=cs, stop_at=1)
        uploaded_chunk = (
            self.uploads_folder + "/" + upload_id + "/" + filename + ".chunk.1"
        )
        merged_file = self.uploads_folder + "/" + filename + "." + upload_id
        # manipulate the data to force an md5 mismatch
        with open(uploaded_chunk, "wb+") as f:
            f.write(b"ffff\n")
        with open(merged_file, "wb+") as f:
            f.write(b"ffff\n")
        token = TEST_TOKENS["VALID"]
        url = f"{self.resumables}/{filename}"
        print("---> resume should fail:")
        # now this _should_ start a new upload due to md5 mismatch
        fileapi.initiate_resumable(
            proj,
            self.test_project,
            filepath,
            token,
            chunksize=cs,
            new=False,
            group=None,
            verify=True,
            upload_id=upload_id,
            dev_url=url,
        )
        res = SerialResumable(self.uploads_folder, "p11-import_user")
        res._db_remove_completed_for_owner(upload_id)

    def test_ZR_cancel_resumable(self) -> None:
        cs = 5
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id = self.start_new_resumable(filepath, chunksize=cs, stop_at=1)
        token = TEST_TOKENS["VALID"]
        # TODO: use client once implemented
        url = f"{self.resumables}/{filename}?id={upload_id}"
        resp = requests.delete(url, headers={"Authorization": "Bearer " + token})
        self.assertEqual(resp.status_code, 200)
        uploaded_folder = self.uploads_folder + "/" + upload_id
        merged_file = self.uploads_folder + "/" + filename + "." + upload_id
        try:
            shutil.rmtree(uploaded_folder)
            os.remove(merged_file)
        except OSError:
            pass

    def test_ZS_recovering_inconsistent_data_allows_resume_from_previous_chunk(
        self,
    ) -> None:
        proj = ""
        token = TEST_TOKENS["VALID"]
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        cs = 5
        upload_id = self.start_new_resumable(filepath, chunksize=cs, stop_at=2)
        url = f"{self.resumables}/{filename}"
        merged_file = self.uploads_folder + "/" + filename + "." + upload_id
        with open(merged_file, "ab") as f:
            f.truncate(int(cs + (cs / 2)))
        # this should trigger data recovery, and restart the resumable at chunk1
        print("---> going to resume from chunk 3, after data recovery:")
        resp = fileapi.initiate_resumable(
            proj,
            self.test_project,
            filepath,
            token,
            chunksize=cs,
            new=False,
            group=None,
            verify=True,
            upload_id=upload_id,
            dev_url=url,
        ).get("response")
        self.assertEqual(resp["max_chunk"], "end")
        self.assertTrue(resp["id"] is not None)
        self.assertEqual(resp["filename"], filename)

    def test_ZT_list_all_resumables(self) -> None:
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        cs = 5
        upload_id1 = self.start_new_resumable(filepath, chunksize=cs, stop_at=2)
        upload_id2 = self.start_new_resumable(filepath, chunksize=cs, stop_at=3)
        token = TEST_TOKENS["VALID"]
        resp = requests.get(
            self.resumables, headers={"Authorization": "Bearer " + token}
        )
        self.assertEqual(resp.status_code, 200)
        uploaded_folder1 = self.uploads_folder + "/" + upload_id1
        uploaded_folder2 = self.uploads_folder + "/" + upload_id2
        merged_file1 = self.uploads_folder + "/" + filename + "." + upload_id1
        merged_file2 = self.uploads_folder + "/" + filename + "." + upload_id2
        try:
            shutil.rmtree(uploaded_folder1)
            shutil.rmtree(uploaded_folder2)
            os.remove(merged_file1)
            os.remove(merged_file2)
            res = SerialResumable(self.uploads_folder, "p11-import_user")
            res._db_remove_completed_for_owner(upload_id1)
            res._db_remove_completed_for_owner(upload_id2)
        except OSError:
            pass

    def test_ZU_sending_uneven_chunks_resume_works(self) -> None:
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id1 = self.start_new_resumable(filepath, chunksize=3, stop_at=1)
        url = f"{self.resumables}/{filename}"
        token = TEST_TOKENS["VALID"]
        print("---> going to resume from chunk 2, with a new chunk size:")
        fileapi.initiate_resumable(
            "",
            self.test_project,
            filepath,
            token,
            chunksize=4,
            new=False,
            group=None,
            verify=True,
            dev_url=url,
            upload_id=upload_id1,
        ).get("response")
        upload = self.uploads_folder + "/" + self.test_group + "/" + filename
        self.assertTrue(await_file(upload))
        self.assertEqual(
            md5sum(filepath),
            md5sum(upload),
        )
        uploaded_folder1 = self.uploads_folder + "/" + upload_id1
        merged_file1 = self.uploads_folder + "/" + filename + "." + upload_id1
        try:
            shutil.rmtree(uploaded_folder1)
            os.remove(merged_file1)
            res = SerialResumable(self.uploads_folder, "p11-import_user")
            res._db_remove_completed_for_owner(upload_id1)
        except OSError:
            pass

    def test_ZV_resume_chunk_order_enforced(self) -> None:
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id = self.start_new_resumable(filepath, chunksize=3, stop_at=2)
        url = f"{self.stream}/{filename}?id={upload_id}&chunk=2"
        token = TEST_TOKENS["VALID"]
        resp = requests.patch(
            url, headers={"Authorization": "Bearer " + token}, data="dddd\n"
        )
        self.assertEqual(resp.status_code, 400)
        url = f"{self.stream}/{filename}?id={upload_id}&chunk=4"
        resp = requests.patch(
            url, headers={"Authorization": "Bearer " + token}, data="dddd\n"
        )
        self.assertEqual(resp.status_code, 400)
        uploaded_folder = self.uploads_folder + "/" + upload_id
        merged_file = self.uploads_folder + "/" + filename + "." + upload_id
        try:
            shutil.rmtree(uploaded_folder)
            os.remove(merged_file)
            res = SerialResumable(self.uploads_folder, "p11-import_user")
            res._db_remove_completed_for_owner(upload_id)
        except OSError:
            pass

    def test_ZW_resumables_access_control(self) -> None:
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        old_user_token = TEST_TOKENS["VALID"]
        upload_id1 = self.start_new_resumable(
            filepath, chunksize=3, stop_at=2, token=old_user_token
        )
        new_user_token = gen_test_token_for_user(self.config, "p11-tommy")
        upload_id2 = self.start_new_resumable(
            filepath, chunksize=3, stop_at=2, token=new_user_token
        )
        # ensure user B cannot list user A's resumable
        resp = requests.get(
            self.resumables, headers={"Authorization": "Bearer " + new_user_token}
        )
        data = json.loads(resp.text)
        for r in data["resumables"]:
            self.assertTrue(str(r["id"]) != str(upload_id1))
        # ensuere user B cannot delete user A's resumable
        url = f"{self.resumables}/{filename}?id={upload_id1}"
        resp = requests.delete(
            url, headers={"Authorization": "Bearer " + new_user_token}
        )
        self.assertEqual(resp.status_code, 403)
        uploaded_folder1 = self.uploads_folder + "/" + upload_id1
        merged_file2 = self.uploads_folder + "/" + filename + "." + upload_id2
        try:
            shutil.rmtree(uploaded_folder1)
            os.remove(merged_file2)
            res = SerialResumable(self.uploads_folder, "p11-import_user")
            res._db_remove_completed_for_owner(upload_id1)
            res = SerialResumable(self.uploads_folder, "p11-tommy")
            res._db_remove_completed_for_owner(upload_id2)
        except OSError:
            pass

    # resume export
    # following spec described here: https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests

    def test_ZX_head_for_export_resume_works(self) -> None:
        url = self.export + "/file1"
        headers = {"Authorization": "Bearer " + TEST_TOKENS["EXPORT"]}
        resp1 = requests.head(url, headers=headers)
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp1.headers["Accept-Ranges"], "bytes")
        self.assertEqual(resp1.headers["Content-Length"], "10")
        etag1 = resp1.headers["Etag"]
        resp2 = requests.head(url, headers=headers)
        self.assertEqual(resp2.status_code, 200)
        etag2 = resp1.headers["Etag"]
        self.assertEqual(etag1, etag2)

    def test_ZY_get_specific_range_for_export(self) -> None:
        url = self.export + "/file1"
        # 10-byte file, with index range: 0,1,2,3,4,5,6,7,8,9
        headers = {
            "Authorization": "Bearer " + TEST_TOKENS["EXPORT"],
            "Range": "bytes=0-3",
        }  # the first 4 bytes in the file
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.headers["Content-Length"], "4")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, "some")
        headers = {
            "Authorization": "Bearer " + TEST_TOKENS["EXPORT"],
            "Range": "bytes=4-7",
        }  # the next 4 bytes in the file
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, " dat")
        headers = {
            "Authorization": "Bearer " + TEST_TOKENS["EXPORT"],
            "Range": "bytes=8-9",
        }  # the last 2 bytes in the file
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, "a\n")

    def test_ZZ_get_range_until_end_for_export(self) -> None:
        url = self.export + "/file1"
        headers = {
            "Authorization": "Bearer " + TEST_TOKENS["EXPORT"],
            "Range": "bytes=5-9",
        }  # 0-indexed, so byte 6 to the end
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, "data\n")

    def test_ZZa_get_specific_range_conditional_on_etag(self) -> None:
        url = self.export + "/file1"
        headers = {"Authorization": "Bearer " + TEST_TOKENS["EXPORT"]}
        resp1 = requests.head(url, headers=headers)
        headers = {
            "Authorization": "Bearer " + TEST_TOKENS["EXPORT"],
            "Range": "bytes=5-",
            "If-Range": resp1.headers["Etag"],
        }
        resp2 = requests.get(url, headers=headers)
        self.assertEqual(resp2.status_code, 200)
        headers = {
            "Authorization": "Bearer " + TEST_TOKENS["EXPORT"],
            "Range": "bytes=5-",
            "If-Range": "0g04d6de2ecd9d1d1895e2086c8785f1",
        }
        resp3 = requests.get(url, headers=headers)
        self.assertEqual(resp3.status_code, 400)

    def test_ZZb_get_range_out_of_bounds_returns_correct_error(self) -> None:
        url = self.export + "/file1"
        headers = {
            "Authorization": "Bearer " + TEST_TOKENS["EXPORT"],
            "Range": "bytes=5-100",
        }
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, 416)

    def test_ZZc_requesting_multiple_ranges_not_supported_error(self) -> None:
        url = self.export + "/file1"
        headers = {
            "Authorization": "Bearer " + TEST_TOKENS["EXPORT"],
            "Range": "bytes=1-4, 5-10",
        }
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, 405)

    def test_ZZe_filename_rules_with_uploads(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        http_client = HTTPClient()

        request = HTTPRequest(
            self.stream + "/" + url_escape("så_søt(1).txt"),
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 201)
        request = HTTPRequest(
            self.stream + "/" + url_escape("rød fil (1).txt"),
            method="PUT",
            body=lazy_file_reader(self.red),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 201)
        request = HTTPRequest(
            self.stream + "/" + url_escape("~not allowed"),
            method="PUT",
            body=lazy_file_reader(self.red),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 400)

        http_client.close()

    # publication system backend

    def test_ZZg_publication(self) -> None:
        # files
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        resp = requests.put(
            self.publication_import + "/" + url_escape("så_søt(1).txt"),
            data=lazy_file_reader(self.so_sweet),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        headers = {"Authorization": "Bearer " + TEST_TOKENS["EXPORT"]}
        resp = requests.get(
            self.publication_export + "/" + url_escape("så_søt(1).txt"),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        # tables
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        resp = requests.put(
            f"{self.publication_tables}/tables/mydata",
            data=json.dumps({"id": str(uuid.uuid4()), "data": [1, 2, 3]}),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(
            f"{self.publication_tables}/tables/mydata",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

    # directories

    def test_ZZZ_put_file_to_dir(self) -> None:
        http_client = HTTPClient()
        # 1. backend where group logic is enabled
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        # nested, not compliant with group requirements
        file = url_escape("file-should-fail.txt")
        request = HTTPRequest(
            f"{self.stream}/mydir1/mydir2/{file}",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 403)
        # nested, no group param
        file = url_escape("file-should-be-in-mydir-ååå.txt")
        request = HTTPRequest(
            f"{self.stream}/p11-member-group/mydir1/mydir2/{file}",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 201)
        # not nested, no group info
        file = url_escape("file-should-be-in-default-group-dir.txt")
        request = HTTPRequest(
            f"{self.stream}/{file}",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 201)

        # not nested, with group param
        file = url_escape("file-should-be-in-default-group-dir2.txt")
        request = HTTPRequest(
            f"{self.stream}/{file}?group=p11-member-group",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 201)
        # inconsistent group info
        file = url_escape("should-not-make-it.txt")
        request = HTTPRequest(
            f"{self.stream}/p11-data-group/mydir1/mydir2/{file}?p11-member-group",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 403)
        # with legacy Filename header
        file = url_escape("should-make-it.txt")
        legacy_headers = headers.copy()
        legacy_headers["Filename"] = file
        request = HTTPRequest(
            f"{self.stream}",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=legacy_headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 201)
        # 2. backend without group logic
        file = url_escape("no-group-logic.txt")
        request = HTTPRequest(
            f"{self.publication_import}/dir1/{file}",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 201)

        http_client.close()

    def test_ZZZ_patch_resumable_file_to_dir(self) -> None:
        self.start_new_resumable(
            self.resume_file1,
            chunksize=5,
            endpoint=f"{self.publication_import}/dir77",
            uploads_folder=f"{self.publication_import_folder}/dir77",
        )

    def test_ZZZ_reserved_resources(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        http_client = HTTPClient()
        # 1. hidden files
        file = url_escape(".resumables-p11-user.db")
        request = HTTPRequest(
            f"{self.publication_import}/{file}",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 400)
        # 2. resumable data folders
        file = url_escape("myfile.chunk.2")
        test_dir = str(uuid.uuid4())
        test_res_dir = f"{self.publication_import_folder}/{test_dir}"
        os.makedirs(test_res_dir)
        with open(f"{self.publication_import_folder}/{test_dir}/{file}", "w") as f:
            f.write("some data")
        request = HTTPRequest(
            f"{self.publication_import}/{test_dir}/{file}",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 400)
        try:
            shutil.rmtree(f"{self.publication_import_folder}/{test_dir}")
        except OSError:
            pass
        # 3. merged resumable files
        file = f"file.{str(uuid.uuid4())}"
        request = HTTPRequest(
            f"{self.publication_import}/{test_dir}/{file}",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 400)
        # 4. parial upload files
        file = f"file.{str(uuid.uuid4())}.part"
        request = HTTPRequest(
            f"{self.publication_import}/{test_dir}/{file}",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 400)
        # 5. export
        file = f"file.{str(uuid.uuid4())}.part"
        request = HTTPRequest(
            f"{self.publication_import}/{test_dir}/{file}",
            method="PUT",
            body=lazy_file_reader(self.so_sweet),
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 400)
        # 6. delete
        file = f"file.{str(uuid.uuid4())}.part"
        request = HTTPRequest(
            f"{self.publication_import}/{test_dir}/{file}",
            method="DELETE",
            headers=headers,
            expect_100_continue=True,
        )
        response = yield http_client.fetch(request)
        self.assertEqual(response.code, 400)
        http_client.close()

    def test_ZZZ_listing_dirs(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["EXPORT"]}
        resp = requests.get(self.export, headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(self.publication_export, headers=headers)
        self.assertEqual(resp.status_code, 200)
        dirs = f"{self.publication_import_folder}/topdir/bottomdir"
        try:
            os.makedirs(dirs)
        except OSError:
            pass
        for i in range(101):
            with open(f"{dirs}/file{i}", "w") as f:
                f.write(f"hi there number {i}")
        resp = requests.get(f"{self.publication_export}/topdir", headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(
            f"{self.publication_export}/topdir/bottomdir", headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(
            f"{self.publication_export}/topdir/bottomdir?page=0&per_page=100",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        data1 = json.loads(resp.text)
        resp = requests.get(
            f"{self.publication_export}/topdir/bottomdir?page=1&per_page=100",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        data2 = json.loads(resp.text)
        self.assertTrue(data2["files"][0] not in data1["files"])
        resp = requests.get(
            f"{self.publication_export}/topdir/bottomdir?page=0&per_page=103",
            headers=headers,
        )
        data = json.loads(resp.text)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(data["files"]), 101)
        # fail gracefully
        resp = requests.get(
            f"{self.publication_export}/topdir/bottomdir?page=-1", headers=headers
        )
        self.assertEqual(resp.status_code, 400)
        resp = requests.get(
            f"{self.publication_export}/topdir/bottomdir?page=blabla", headers=headers
        )
        self.assertEqual(resp.status_code, 400)
        resp = requests.get(
            f"{self.publication_export}/topdir/bottomdir?page=1&per_page=500001",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 400)
        try:
            shutil.rmtree(f"{dirs}")
        except OSError:
            pass
        # posix backend
        resp = requests.get(f"{self.export}/data-folder", headers=headers)
        self.assertEqual(resp.status_code, 200)

    def test_ZZZ_listing_import_dir(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        # top level
        # no group included
        resp = requests.get(f"{self.stream}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        # trying a group that the requestor is not a member of
        # will have APIgrant  level access control in addition
        resp = requests.get(f"{self.stream}/p11-bla-group", headers=headers)
        self.assertEqual(resp.status_code, 403)
        # with necessary membership (reporting modified_date by default)
        resp = requests.get(f"{self.stream}/p11-member-group", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.text)
        self.assertTrue(data["files"][0]["modified_date"] is not None)
        # leaving out modified_date if requested
        resp = requests.get(
            f"{self.stream}/p11-member-group?disable_metadata=true", headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.text)
        self.assertTrue(data["files"][0]["modified_date"] is None)
        # allowed
        target = os.path.basename(self.so_sweet)
        resp = requests.put(
            f"{self.stream}/p11-member-group/{target}",
            data=lazy_file_reader(self.so_sweet),
            headers=headers,
        )
        resp = requests.head(
            f"{self.stream}/p11-member-group/{target}", headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue("Etag" in resp.headers.keys())
        # not allowed
        resp = requests.head(f"{self.stream}/p11-bla-group/{target}", headers=headers)
        self.assertEqual(resp.status_code, 403)

    def test_ZZZ_get_file_from_dir(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["EXPORT"]}
        dirs = f"{self.publication_import_folder}/topdir/bottomdir"
        try:
            os.makedirs(dirs)
        except OSError:
            pass
        with open(f"{dirs}/file1", "w") as f:
            f.write("hi there")
        with open(f"{dirs}/file2", "w") as f:
            f.write("how are you?")
        resp = requests.get(
            f"{self.publication_export}/topdir/bottomdir/file1", headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, "hi there")
        resp = requests.head(
            f"{self.publication_export}/topdir/bottomdir/file1", headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.head(
            f"{self.publication_export}/topdir/bottomdir", headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        try:
            shutil.rmtree(f"{dirs}")
        except OSError:
            pass

    def test_ZZZ_delete(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["EXPORT"]}
        dirs = f"{self.publication_import_folder}/topdir/bottomdir"
        resp = requests.put(
            f"{self.publication_import}/topdir/bottomdir/file1",
            data=lazy_file_reader(self.so_sweet),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.delete(f"{self.publication_export}", headers=headers)
        self.assertEqual(resp.status_code, 400)
        resp = requests.delete(f"{self.publication_export}/", headers=headers)
        self.assertEqual(resp.status_code, 400)
        resp = requests.delete(
            f"{self.publication_export}/topdir/bottomdir/file1", headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue("file1" not in os.listdir(dirs))
        resp = requests.delete(
            f"{self.publication_export}/topdir/bottomdir", headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.delete(
            f"{self.publication_export}/topdir/bottomdir/nofile", headers=headers
        )
        self.assertEqual(resp.status_code, 404)
        try:
            shutil.rmtree(f"{dirs}")
        except OSError:
            pass

    def test_token_signature_validation(self) -> None:
        test_header = "Bearer " + TEST_TOKENS["TEST_SIG"]
        res = process_access_token(
            test_header,
            self.test_project,
            self.config["token_check_tenant"],
            self.config["token_check_exp"],
            self.config["tenant_claim_name"],
            self.config["jwt_test_secret"],
        )
        self.assertTrue(res["status"])

    def test_app_backend(self) -> None:
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        file = url_escape("genetic-data.bam")
        resp = requests.put(
            f"{self.apps}/ega/files/user1/{file}",
            data=lazy_file_reader(self.so_sweet),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(f"{self.apps}/ega/files/user1/{file}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.head(f"{self.apps}/ega/files/user1/{file}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.delete(f"{self.apps}/ega/files/user1/{file}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.start_new_resumable(
            self.resume_file1,
            chunksize=5,
            endpoint=f"{self.apps}/ega/files/user1",
            uploads_folder=f"{self.apps_import_folder}/ega/files/user1",
        )
        source_data = [
            {"key1": 7, "key2": "bla", "id": random.randint(0, 1000000)},
            {"key1": 99, "key3": False, "id": random.randint(0, 1000000)},
        ]
        headers["Content-Type"] = "application/json"
        headers["Resource-Identifier-Key"] = "id"
        # clear the tables
        try:
            resp = requests.delete(
                f"{self.apps}/ega/tables/user_data?where=key1=gte.0", headers=headers
            )
        except Exception:
            pass
        try:
            resp = requests.delete(
                f"{self.apps}/ega/tables/user_data/metadata?where=key1=gte.0",
                headers=headers,
            )
        except Exception:
            pass
        try:
            resp = requests.delete(
                f"{self.apps}/ega/tables/persons/pid1", headers=headers
            )
        except Exception:
            pass
        try:
            resp = requests.delete(f"{self.apps}/ega/tables/lol", headers=headers)
        except Exception:
            pass

        # add some data
        resp = requests.put(
            f"{self.apps}/ega/tables/user_data",
            data=json.dumps(source_data),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        # idempotent
        resp = requests.put(
            f"{self.apps}/ega/tables/user_data",
            data=json.dumps(source_data),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(f"{self.apps}/ega/tables/user_data", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.text)
        self.assertEqual(len(data), 2)

        # "sub"-tables
        resp = requests.put(
            f"{self.apps}/ega/tables/persons/pid1",
            data=json.dumps(source_data),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)

        # edit
        new_version = {"key1": 6}
        resp = requests.patch(
            f"{self.apps}/ega/tables/user_data?set=key1&where=key1=eq.7",
            headers=headers,
            data=json.dumps(new_version),
        )
        self.assertEqual(resp.status_code, 201)

        # audit
        resp = requests.get(f"{self.apps}/ega/tables/user_data/audit", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.text)
        self.assertTrue(data)
        self.assertEqual(data[0].get("diff"), new_version)
        self.assertEqual(data[0].get("identity_name"), "Test Test")

        # metadata
        resp = requests.put(
            f"{self.apps}/ega/tables/user_data/metadata",
            data=json.dumps(source_data),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)

        # listing tables
        resp = requests.get(f"{self.apps}/ega/tables", headers=headers)
        app_tables = json.loads(resp.text)
        self.assertEqual(len(app_tables.get("tables")), 3)

        # clean up
        resp = requests.delete(f"{self.apps}/ega/tables/user_data", headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.delete(
            f"{self.apps}/ega/tables/user_data/metadata", headers=headers
        )
        self.assertEqual(resp.status_code, 200)

        # test delete semantics - on audit too
        resp = requests.get(f"{self.apps}/ega/tables/user_data", headers=headers)
        self.assertEqual(resp.status_code, 404)
        resp = requests.get(f"{self.apps}/ega/tables/user_data/audit", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(json.loads(resp.text)) > 0)

        # test query features
        data = [
            {"id": 1, "cat": "&", "comment": "dis 'n mooi dag"},
            {"id": 2, "cat": None},
            {"id": 3, "cat": "yes"},
        ]
        resp = requests.put(
            f"{self.apps}/ega/tables/lol",
            data=json.dumps(data),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)

        # ampersand in where
        resp = requests.get(
            f"{self.apps}/ega/tables/lol?select=id&where=cat=eq.'&'",
            headers=headers,
        )
        self.assertEqual(json.loads(resp.text), [[1]])

        # escaping a single quote
        resp = requests.get(
            f"{self.apps}/ega/tables/lol?select=id&where=comment=eq.'dis \\'n mooi dag'",
            headers=headers,
        )
        self.assertEqual(json.loads(resp.text), [[1]])

        # cleanup
        resp = requests.delete(f"{self.apps}/ega/tables/lol", headers=headers)
        self.assertEqual(resp.status_code, 200)

        # backup and restoring files

        file = "some.data"
        resp = requests.put(
            f"{self.apps}/ega/files/dir1/{file}",
            data=lazy_file_reader(self.so_sweet),
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)

        resp = requests.delete(
            f"{self.apps}/ega/files/dir1/{file}",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

        # check the backup
        resp = requests.get(
            f"{self.apps}/ega/backup/files/dir1",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            json.loads(resp.text).get("files")[0].get("filename"),
            "some.data",
        )

        # restore the file
        resp = requests.post(
            f"{self.apps}/ega/backup/files/dir1/{file}?restore",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(json.loads(resp.text).get("restores")), 1)

        # remove it completely
        resp = requests.delete(
            f"{self.apps}/ega/files/dir1/{file}",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.delete(
            f"{self.apps}/ega/backup/files/dir1/{file}",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

    def test_app_backend_encryption(self) -> None:
        """Test app backend with encrypted retrieval of data."""

        def decrypt_response(
            response: bytes, chunk_size: int, nonce: bytes, key: bytes
        ) -> str:
            """Decrypt the response in chunks specified by chunk_size."""
            decrypted_response = b""
            for chunk in range(math.ceil(len(response) / chunk_size)):
                decrypted_response += libnacl.crypto_stream_xor(
                    response[chunk * chunk_size : (chunk + 1) * chunk_size],
                    nonce,
                    key,
                )
            return decrypted_response.decode("utf-8")

        app = f"{self.apps}/{''.join(random.choices(string.ascii_lowercase, k=20))}"
        data_table = f"{app}/tables/data"
        source_data = [
            {"key_a": "🤡", "key_b": "💐", "id": random.randint(0, 1000000)},
            {
                "key_a": str(uuid.uuid4()),
                "key3": False,
                "id": random.randint(0, 1000000),
            },
        ]
        headers = {"Authorization": "Bearer " + TEST_TOKENS["VALID"]}
        headers["Content-Type"] = "application/json"
        headers["Resource-Identifier-Key"] = "id"

        # create app and add some data to the data table
        response = requests.put(
            data_table,
            data=json.dumps(source_data),
            headers=headers,
        )
        self.assertEqual(response.status_code, 201)
        response = requests.get(data_table, headers=headers)
        self.assertEqual(response.status_code, 200)

        # cleartext get
        response = requests.get(
            data_table,
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        cleartext_response = response.text

        # sealed box setup for server pubkey
        response = requests.get(f"{self.apps}/crypto/key")
        encoded_public_key = response.json().get("public_key")
        public_key = libnacl.public.PublicKey(base64.b64decode(encoded_public_key))
        client_sealed_box = libnacl.sealed.SealedBox(public_key)

        # client secrets
        key = libnacl.utils.salsa_key()
        nonce = libnacl.utils.rand_nonce()
        cipher_text_key = client_sealed_box.encrypt(key)
        cipher_text_nonce = client_sealed_box.encrypt(nonce)

        # header setup for encryption
        encryption_headers = headers.copy()
        nacl_key = base64.b64encode(cipher_text_key)
        nacl_nonce = base64.b64encode(cipher_text_nonce)
        nacl_chunksize = 16384  # 16 KiB
        content_type = "application/octet-stream+nacl"
        encryption_headers["Nacl-Nonce"] = nacl_nonce
        encryption_headers["Nacl-Key"] = nacl_key
        encryption_headers["Nacl-Chunksize"] = str(nacl_chunksize)
        encryption_headers["Content-Type"] = content_type

        # encrypted get
        response = requests.get(
            data_table,
            headers=encryption_headers,
        )
        self.assertEqual(response.status_code, 200)

        # assert the encrypted response is not the same as the cleartext response
        self.assertNotEqual(cleartext_response, response.text)

        # decrypt each chunk of the encrypted response
        encrypted_response = response.content
        decrypted_data = decrypt_response(
            encrypted_response, nacl_chunksize, nonce, key
        )

        # assert that the decrypted response is the same as the cleartext response
        self.assertEqual(decrypted_data, cleartext_response)

        # get some specific data in cleartext
        query = f"{data_table}?select=key_a"
        response = requests.get(
            query,
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        cleartext_key_a = response.text

        # request same data encrypted
        response = requests.get(
            query,
            headers=encryption_headers,
        )
        self.assertEqual(response.status_code, 200)

        # decrypt data
        encrypted_key_a = response.content
        decrypted_key_a = decrypt_response(encrypted_key_a, nacl_chunksize, nonce, key)

        # verify that we have gotten the same data after decryption
        self.assertEqual(decrypted_key_a, cleartext_key_a)

        # cleartext get for non-existing data
        query = f"{data_table}?where=id=eq.🤡"
        response = requests.get(
            query,
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        cleartext_empty_response = response.text

        # encrypted get for non-existing data
        response = requests.get(
            query,
            headers=encryption_headers,
        )
        self.assertEqual(response.status_code, 200)

        # decode the decrypted response's UTF-8 data
        encrypted_empty_response = response.content
        decrypted_empty_data = decrypt_response(
            encrypted_empty_response, nacl_chunksize, nonce, key
        )

        # assert that the decrypted response is the same as the cleartext response
        self.assertEqual(decrypted_empty_data, cleartext_empty_response)

        # cleanup
        resp = requests.delete(data_table, headers=headers)
        self.assertEqual(resp.status_code, 200)

        # test delete semantics - on audit too
        resp = requests.get(f"{data_table}", headers=headers)
        self.assertEqual(resp.status_code, 404)
        resp = requests.get(f"{data_table}/audit", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(json.loads(resp.text)) > 0)

    def test_nacl_crypto(self) -> None:
        # https://libnacl.readthedocs.io/en/latest/index.html

        # server key pair
        server_public_key = base64.b64decode(self.config["test_nacl_public"]["public"])
        server_private_key = base64.b64decode(
            self.config["test_nacl_public"]["private"]
        )

        # client
        # Note: for browser clients, e.g.:
        # https://github.com/bcomnes/nacl-blob and https://nacl-blob.netlify.app/
        # https://github.com/tonyg/js-nacl#secret-key-encryption-crypto_stream
        # 1. generate a client secret key and nonce
        nonce = libnacl.utils.rand_nonce()
        key = libnacl.utils.salsa_key()

        # 2. use it to encrypt payload
        payload = "hi there"
        encrypted_payload = libnacl.crypto_stream_xor(payload.encode(), nonce, key)

        # 3. use server public key encrypt client secret key, and nonce
        client_sealed_box = libnacl.sealed.SealedBox(
            libnacl.public.PublicKey(server_public_key)
        )
        cipher_text_key = client_sealed_box.encrypt(key)
        cipher_text_nonce = client_sealed_box.encrypt(nonce)

        # server
        # 1. decrypt the client secret key
        server_sealed_box = libnacl.sealed.SealedBox(
            libnacl.public.SecretKey(server_private_key)
        )
        decrypted_client_key = server_sealed_box.decrypt(cipher_text_key)
        decrypted_client_nonce = server_sealed_box.decrypt(cipher_text_nonce)
        assert key == decrypted_client_key
        assert nonce == decrypted_client_nonce

        # 2. decrypt the encrypted payload
        decrypted_payload = libnacl.crypto_stream_xor(
            encrypted_payload, decrypted_client_nonce, decrypted_client_key
        )
        assert decrypted_payload.decode() == payload

        # write an encryptde stream to a file (save a stream)
        chunk_size = 10
        with open("/tmp/lines", "w") as f:
            for i in range(20):
                f.write(f"{i} good day sir, hwo are you doing? ")
            f.write("good bye")
        test_file = "/tmp/lines"
        enc_test_file = test_file + ".stream"
        dec_test_file = test_file + ".decr"
        with open(test_file, "rb") as fplain:
            with open(enc_test_file, "wb") as fcipher:
                while True:
                    data = fplain.read(chunk_size)
                    if not data:
                        break
                    enc = libnacl.crypto_stream_xor(data, nonce, key)
                    fcipher.write(enc)

        # Simulate getting chunks of different sizes form the network
        # some being too small, and others being too large
        # with respect to the chunk size used to create the encrypted stream.
        # Then recipient (server) needs to accumulate incoming chunks
        # in a buffer, and process the correct sized
        # chunks from that buffer
        _buffer = b""
        small_chunk = chunk_size - 3
        larger_chunk = chunk_size + 1
        line_no = 0
        with open(dec_test_file, "wb") as fdecrypted:
            with open(enc_test_file, "rb") as fsmaller:
                while True:
                    line_no += 1
                    if line_no % 2 == 0:
                        size = small_chunk
                    else:
                        size = larger_chunk
                    chunk = fsmaller.read(size)
                    for byte in chunk:
                        _buffer += bytes([byte])
                        if len(_buffer) % chunk_size == 0:
                            decr = libnacl.crypto_stream_xor(_buffer, nonce, key)
                            fdecrypted.write(decr)
                            _buffer = b""
                    if not chunk:
                        break
                if len(_buffer) > 0:
                    decr = libnacl.crypto_stream_xor(_buffer, nonce, key)
                    fdecrypted.write(decr)

        self.assertTrue(await_file(dec_test_file))
        assert md5sum(test_file) == md5sum(dec_test_file)

        # now with requests to the survey backend
        # client setup steps
        resp = requests.get(f"{self.base_url}/survey/crypto/key")
        encoded_public_key = json.loads(resp.text).get("public_key")
        public_key = libnacl.public.PublicKey(base64.b64decode(encoded_public_key))
        sbox = libnacl.sealed.SealedBox(public_key)
        nonce = libnacl.utils.rand_nonce()
        key = libnacl.utils.salsa_key()
        chunk_size = 5
        # save a new encrypted stream to a file, with new nonce, and key
        # this could be generated on the fly while reading the file
        # TODO: test this with a large file
        new_stream = test_file + ".new.stream"
        with open(test_file, "rb") as fin:
            with open(new_stream, "wb") as fout:
                while True:
                    data = fin.read(chunk_size)
                    if not data:
                        break
                    enc = libnacl.crypto_stream_xor(data, nonce, key)
                    fout.write(enc)

        # prepare request params
        nacl_nonce = base64.b64encode(sbox.encrypt(nonce))
        nacl_key = base64.b64encode(sbox.encrypt(key))
        nacl_chunksize = chunk_size
        content_type = "application/octet-stream+nacl"

        # send encrypted data, chunk-wise
        target = "123456/attachments/auto-decrypt1"
        resp = requests.put(
            f"{self.survey}/{target}",
            headers={
                "Content-Type": content_type,
                "Nacl-Nonce": nacl_nonce,
                "Nacl-Key": nacl_key,
                "Nacl-Chunksize": str(nacl_chunksize),
                "Authorization": f"Bearer {TEST_TOKENS['VALID']}",
            },
            data=lazy_file_reader(new_stream),
        )
        upload = f"{self.uploads_folder_survey}/{target}"
        self.assertTrue(await_file(upload))
        self.assertEqual(md5sum(test_file), md5sum(upload))

        # send encrypted data, all in one
        target = "123456/attachments/auto-decrypt2"
        resp = requests.put(
            f"{self.survey}/{target}",
            headers={
                "Content-Type": content_type,
                "Nacl-Nonce": nacl_nonce,
                "Nacl-Key": nacl_key,
                "Nacl-Chunksize": str(nacl_chunksize),
                "Authorization": f"Bearer {TEST_TOKENS['VALID']}",
            },
            data=open(new_stream, "rb").read(),
        )
        upload = f"{self.uploads_folder_survey}/{target}"
        self.assertTrue(await_file(upload))
        self.assertEqual(md5sum(test_file), md5sum(upload))

        # send as a resumable
        self.start_new_resumable(self.resume_file1, chunksize=5, public_key=public_key)

        # test refuse too large chunk size
        resp = requests.put(
            f"{self.survey}/{target}",
            headers={
                "Content-Type": content_type,
                "Nacl-Nonce": nacl_nonce,
                "Nacl-Key": nacl_key,
                "Nacl-Chunksize": str(52428801),
                "Authorization": f"Bearer {TEST_TOKENS['VALID']}",
            },
            data=open(new_stream, "rb").read(),
        )
        self.assertTrue(resp.status_code, 400)

        payload1 = {
            "x": 10,
            "y": 0,
            "more": "all the data yay",
            "id": str(uuid.uuid4()),
        }
        payload2 = [
            {"id": str(uuid.uuid4()), "answers": [i for i in range(1000)]},
            {"id": str(uuid.uuid4()), "answers": [i for i in range(100)]},
            {"id": str(uuid.uuid4()), "answers": [i for i in range(10000)]},
        ]

        def encrypt_json(data, nonce, key):
            # return encrypted payload
            # and length of serialised, byte encoded json
            serialised = json.dumps(data).encode()
            enc = libnacl.crypto_stream_xor(serialised, nonce, key)
            return enc, len(serialised)

        target = "444222/submissions"
        for payload in [payload1, payload2]:
            encrypted, chunksize = encrypt_json(payload, nonce, key)
            resp = requests.put(
                f"{self.survey}/{target}",
                headers={
                    "Content-Type": "application/json+nacl",
                    "Nacl-Nonce": nacl_nonce,
                    "Nacl-Key": nacl_key,
                    "Nacl-Chunksize": str(chunksize),
                    "Authorization": f"Bearer {TEST_TOKENS['VALID']}",
                },
                data=encrypted,
            )
            self.assertTrue(resp.status_code, 201)

        # test refuse too large chunk sizes
        resp = requests.put(
            f"{self.survey}/{target}",
            headers={
                "Content-Type": "application/json+nacl",
                "Nacl-Nonce": nacl_nonce,
                "Nacl-Key": nacl_key,
                "Nacl-Chunksize": str(500001),
                "Authorization": f"Bearer {TEST_TOKENS['VALID']}",
            },
            data=encrypted,
        )
        self.assertTrue(resp.status_code, 400)

        # encrypted downloads
        headers = {
            "Nacl-Nonce": nacl_nonce,
            "Nacl-Key": nacl_key,
            "Nacl-Chunksize": str(10),
            "Authorization": f"Bearer {TEST_TOKENS['VALID']}",
        }
        # without client-side decryption
        resp = requests.get(self.export + "/file1", headers=headers)
        self.assertTrue(resp.text != "some data\n")
        self.assertEqual(resp.status_code, 200)
        # with client-side decryption
        fileapi.export_get(
            "",  # no env
            self.test_project,
            "file1",
            TEST_TOKENS["VALID"],
            2,  # chunksize
            dev_url=f"{self.export}/file1",
            public_key=public_key,
            target_dir="/tmp",
        )
        self.assertEqual(open("/tmp/file1").read(), "some data\n")

        requests.delete(f"{self.survey}/{target}", headers=headers)

    def test_maintenance_mode(self) -> None:
        maintenance_on = f"{self.maintenance_url}?maintenance=on"
        maintenance_off = f"{self.maintenance_url}?maintenance=off"
        resp = requests.post(maintenance_on)
        resp = requests.put(self.sns_upload)
        self.assertEqual(resp.status_code, 503)
        resp = requests.get(f"{self.base_url}/files/resumables")
        self.assertEqual(resp.status_code, 503)
        resp = requests.put(f"{self.base_url}/files/stream/file")
        self.assertEqual(resp.status_code, 503)
        resp = requests.patch(f"{self.base_url}/files/stream/file")
        self.assertEqual(resp.status_code, 503)
        resp = requests.get(f"{self.base_url}/files/export/file1")
        self.assertEqual(resp.status_code, 503)
        resp = requests.head(f"{self.base_url}/files/export/file2")
        self.assertEqual(resp.status_code, 503)
        resp = requests.get(f"{self.base_url}/survey")
        self.assertEqual(resp.status_code, 503)
        resp = requests.put(f"{self.base_url}/survey/12345/submissions")
        self.assertEqual(resp.status_code, 503)
        resp = requests.post(maintenance_off)

    def test_mtime_functionality(self) -> None:
        # setting mtime on upload
        original_file_mtime = os.stat(self.so_sweet).st_mtime
        headers = {
            "Authorization": "Bearer " + TEST_TOKENS["VALID"],
            "Modified-Time": str(original_file_mtime),
        }
        name = "file-with-mtime.txt"
        file = url_escape(name)
        url = f"{self.stream}/{self.test_group}/{file}"
        resp = requests.put(url, data=lazy_file_reader(self.so_sweet), headers=headers)
        self.assertEqual(resp.status_code, 201)
        upload = f"{self.uploads_folder}/{self.test_group}/{name}"
        self.assertTrue(await_file(upload))

        # verify uploaded file has the same mtime as specified in the header
        @backoff.on_exception(backoff.expo, AssertionError, max_time=2)
        def await_same_mtime(file, reference_mtime):
            self.assertEqual(os.stat(file).st_mtime, reference_mtime)

        await_same_mtime(file=upload, reference_mtime=original_file_mtime)

        # with info
        resp = requests.head(url, headers=headers)
        self.assertEqual(float(resp.headers.get("Modified-Time")), original_file_mtime)
        # with list
        resp = requests.get(url.replace(f"/{name}", ""), headers=headers)
        data = json.loads(resp.text)
        for entry in data["files"]:
            if entry["filename"] == name:
                self.assertEqual(entry["mtime"], original_file_mtime)
        # with download
        url = f"{self.apps}/app1/files/{name}"
        resp = requests.put(url, data=lazy_file_reader(self.so_sweet), headers=headers)
        resp = requests.get(url, headers=headers)
        self.assertEqual(float(resp.headers.get("Modified-Time")), original_file_mtime)

    def test_log_viewer(self) -> None:
        headers = {"Authorization": f"Bearer {TEST_TOKENS['VALID']}"}
        resp = requests.get(f"{self.logs}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        available_backends = json.loads(resp.text).get("logs")
        self.assertTrue(isinstance(available_backends, list))
        for backend in ["files_import", "files_export", "apps/ega"]:
            resp = requests.get(f"{self.logs}/{backend}", headers=headers)
            self.assertEqual(resp.status_code, 200)
        resp = requests.get(f"{self.logs}/apps", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(isinstance(json.loads(resp.text).get("apps"), list))
        # and that aggregations work
        resp = requests.get(
            f"{self.logs}/files_export?select=count(1)", headers=headers
        )
        self.assertEqual(resp.status_code, 200)

    def test_find_tenant_storage_path(self) -> None:
        td = tempfile.TemporaryDirectory()
        root = td.name
        os.makedirs(f"{root}/projects01/p11/data/durable")
        os.makedirs(f"{root}/projects02/p12/.from-hnas/data/durable")

        class Options:
            tenant_storage_cache = {}
            prefer_ess = ["files_import", "files_export"]

        opts = Options()
        # choose ess
        self.assertTrue(
            find_tenant_storage_path(
                "p11",
                "files_import",
                opts,
                root=root,
            ).endswith("/projects01/p11/data/durable")
        )


def main() -> None:
    tests = []
    base = [
        # authz
        "test_D_timed_out_token_rejected",
        "test_E_unauthenticated_request_rejected",
        # tenant logic
        "test_Y_invalid_project_number_rejected",
        "test_Z_token_for_other_project_rejected",
        # upload dirs
        "test_ZA_choosing_file_upload_directories_based_on_tenant_works",
        "test_ZD_cannot_upload_empty_file_to_sns",
        # groups
        "test_ZE_stream_works_with_client_specified_group",
        # TODO: add new group tests
        # resume
        "test_ZM_resume_new_upload_works_is_idempotent",
        "test_ZN_resume_works_with_upload_id_match",
        "test_ZO_resume_works_with_filename_match",
        "test_ZP_resume_do_not_upload_if_md5_mismatch",
        "test_ZR_cancel_resumable",
        "test_ZS_recovering_inconsistent_data_allows_resume_from_previous_chunk",
        "test_ZT_list_all_resumables",
        "test_ZU_sending_uneven_chunks_resume_works",
        "test_ZV_resume_chunk_order_enforced",
        "test_ZW_resumables_access_control",
        # publication backend
        "test_ZZg_publication",
    ]
    sns = [
        "test_H1_put_file_multi_part_form_data_sns",
        "test_H5XX_when_no_keydir_exists",
        "test_ZB_sns_folder_logic_is_correct",
    ]
    names = [
        "test_ZZe_filename_rules_with_uploads",
    ]
    basic_to_stream = [
        "test_I_put_file_to_streaming_endpoint_no_chunked_encoding_data_binary",
        "test_K_put_stream_file_chunked_transfer_encoding",
    ]
    export = [
        # export
        "test_ZJ_export_file_restrictions_enforced",
        "test_ZK_export_list_dir_works",
        "test_ZL_export_file_works",
        # resume export
        "test_ZX_head_for_export_resume_works",
        "test_ZY_get_specific_range_for_export",
        "test_ZZ_get_range_until_end_for_export",
        "test_ZZa_get_specific_range_conditional_on_etag",
        "test_ZZb_get_range_out_of_bounds_returns_correct_error",
    ]
    dirs = [
        "test_ZZZ_put_file_to_dir",
        "test_ZZZ_patch_resumable_file_to_dir",
        "test_ZZZ_get_file_from_dir",
        "test_ZM2_resume_upload_with_directory",
    ]
    listing = [
        "test_ZZZ_listing_dirs",
        "test_ZZZ_listing_import_dir",
    ]
    delete = [
        "test_ZZZ_delete",
    ]
    reserved = [
        "test_ZZZ_reserved_resources",
    ]
    sig = [
        "test_token_signature_validation",
    ]
    ns = [
        "test_XXX_query_invalid",
        "test_XXX_nettskjema_backend",
        "test_survey_api_queries",
    ]
    tables = [
        "test_tables",
    ]
    load = ["test_XXX_load"]
    apps = [
        "test_app_backend",
        "test_app_backend_encryption",
    ]
    crypt = ["test_nacl_crypto"]
    maintenance = [
        "test_maintenance_mode",
    ]
    mtime = [
        "test_mtime_functionality",
    ]
    logs = [
        "test_log_viewer",
    ]
    storage = [
        "test_find_tenant_storage_path",
    ]
    if len(sys.argv) == 1:
        sys.argv.append("all")
    elif len(sys.argv) == 2:
        print("usage:")
        print("python3 tsdfileapi/test_file_api.py config.yaml ARGS")
        print(
            "ARGS: all, base, names, pipelines, export, basic-stream, gpg, dirs, listing"
        )
        sys.exit(0)
    if "base" in sys.argv:
        tests.extend(base)
    if "sns" in sys.argv:
        tests.extend(sns)
    if "names" in sys.argv:
        tests.extend(names)
    if "dirs" in sys.argv:
        tests.extend(dirs)
    if "export" in sys.argv:
        tests.extend(export)
    if "basic-stream" in sys.argv:
        tests.extend(basic_to_stream)
    if "reserved" in sys.argv:
        tests.extend(reserved)
    if "listing" in sys.argv:
        tests.extend(listing)
    if "delete" in sys.argv:
        tests.extend(delete)
    if "sig" in sys.argv:
        tests.extend(sig)
    if "ns" in sys.argv:
        tests.extend(ns)
    if "load" in sys.argv:
        tests.extend(load)
    if "apps" in sys.argv:
        tests.extend(apps)
    if "crypt" in sys.argv:
        tests.extend(crypt)
    if "maintenance" in sys.argv:
        tests.extend(maintenance)
    if "mtime" in sys.argv:
        tests.extend(mtime)
    if "logs" in sys.argv:
        tests.extend(logs)
    if "storage" in sys.argv:
        tests.extend(storage)
    if "tables" in sys.argv:
        tests.extend(tables)
    if "all" in sys.argv:
        tests.extend(base)
        tests.extend(sns)
        tests.extend(names)
        tests.extend(dirs)
        tests.extend(export)
        tests.extend(basic_to_stream)
        tests.extend(reserved)
        tests.extend(listing)
        tests.extend(delete)
        tests.extend(sig)
        tests.extend(ns)
        tests.extend(apps)
        tests.extend(crypt)
        tests.extend(mtime)
        tests.extend(logs)
        tests.extend(tables)
    tests.sort()
    suite = unittest.TestSuite()
    for test in tests:
        suite.addTest(TestFileApi(test))
    runner = unittest.TextTestRunner()
    #    runner = unittest.TextTestRunner(verbosity=3, failfast=True)
    result = runner.run(suite)
    # in Python int(True) is 1, int(False) is 0
    sys.exit(not result.wasSuccessful())


if __name__ == "__main__":
    main()
