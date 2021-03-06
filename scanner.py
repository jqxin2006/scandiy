import json
import logging
import uuid
from wsgiref import simple_server
import falcon
import requests
import queue
import ConfigParser
import base64
import zlib
from retrying import retry
import logging
import logging.handlers

LOG_FILENAME = './logs/scanner.log'
# Set up a specific logger with our desired output level
my_logger = logging.getLogger('apinode')
my_logger.setLevel(logging.DEBUG)

# Add the log message handler to the logger
handler = logging.handlers.RotatingFileHandler(LOG_FILENAME,
                                               maxBytes=2000000,
                                               backupCount=10,
                                               )
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
my_logger.addHandler(handler)


class ScanEngine(object):

    @retry(stop_max_attempt_number=7, wait_fixed=5000)
    def get_scans(self):
        config = ConfigParser.ConfigParser()
        config.read("general.config")
        client_id = config.get("apinode", "client_id")
        try:
            the_scan = queue.ScanQueue(my_logger=my_logger)
            the_messages = the_scan.get_queue_messages(client_id=client_id)
            return the_messages
        except Exception as ex:
            my_logger.error(ex)

    @retry(stop_max_attempt_number=7, wait_fixed=5000)
    def find_scan_in_queue(self, scan_id="", queue_name="ScanRequest"):
        """Find whether the given scan is in the given queue

        Find whether the given queue contains the given scan. It returns
        Ture is the matched scan is found. Otherwise, it returns False.
        """
        config = ConfigParser.ConfigParser()
        config.read("general.config")
        client_id = config.get("apinode", "client_id")
        try:

            the_scan = queue.ScanQueue(my_logger=my_logger)
            the_messages = the_scan.get_queue_messages(queue_name=queue_name,
                                                       client_id=client_id)
            my_logger.debug("check {} for scan wth id {}".format(
                                        queue_name, scan_id))

            if len(the_messages) < 1:
                return False
            else:
                for message in the_messages["messages"]:
                    if message["body"]["scan_id"] == scan_id:
                        return True
                return False
        except Exception as ex:
            my_logger.error(ex)

    @retry(stop_max_attempt_number=7, wait_fixed=5000)
    def get_scan_status(self, scan_id=""):
        """Return the status of the scan

        Returns the status of the scan based on the scan id. It checks both
        ScanResponse and ScanRequest queues for the scan. If none is found
        a message with "not found" is returned. If a matched one is found
        in ScanRequest only, "not started" is returned. If a matched one is
        found in ScanResponse only, the status within the queue is returned
        with possible scan results.

        """

        config = ConfigParser.ConfigParser()
        config.read("general.config")
        client_id = config.get("apinode", "client_id")
        the_scan = queue.ScanQueue(my_logger=my_logger)

        try:
            if (self.find_scan_in_queue(queue_name="ScanRequest",
                                        scan_id=scan_id) == False and
                self.find_scan_in_queue(queue_name="ScanResponse",
                                        scan_id=scan_id) == False):
                return "{{'id':{}, 'status':'not found'}}".format(scan_id)

            if (self.find_scan_in_queue(queue_name="ScanRequest",
                                        scan_id=scan_id) == True and
                self.find_scan_in_queue(queue_name="ScanResponse",
                                        scan_id=scan_id) == False):
                return "{{'id':{}, 'status':'not started'}}".format(scan_id)

            if (self.find_scan_in_queue(queue_name="ScanResponse",
                                        scan_id=scan_id) == True):
                the_messages = the_scan.get_queue_messages(
                                        queue_name="ScanResponse",
                                        client_id=client_id)
                the_result = "{}"
                for message in the_messages["messages"]:
                    my_logger.debug("found scan with id={}".format(
                            message["body"]["scan_id"]))
                    if message["body"]["scan_id"] == scan_id:
                        the_result = message["body"]
                        if the_result["status"] == "scan finished":
                            temp_scan_result = the_result["scan_result"]
                            the_result["scan_result"] = base64.b64decode(
                                temp_scan_result).decode("zlib")
                            return the_result
                        else:
                            return the_result
                return the_result
        except Exception as ex:
            my_logger.error(ex)

    @retry(stop_max_attempt_number=7, wait_fixed=5000)
    def add_scan(self, thing):
        config = ConfigParser.ConfigParser()
        config.read("general.config")
        client_id = config.get("apinode", "client_id")
        the_scan = queue.ScanQueue(my_logger=my_logger)
        my_logger.debug("adding the scan")
        my_logger.info("create scan with the body {}".format(thing))
        scan_id = the_scan.post_queue_message(client_id=client_id, body=thing)
        my_logger.info("create scan with id {}".format(scan_id))
        return scan_id


class StorageError(Exception):

    @staticmethod
    def handle(ex, req, resp, params):
        description = ('Sorry, couldn\'t write your thing to the '
                       'database. It worked on my box.')

        raise falcon.HTTPError(falcon.HTTP_725,
                               'Database Error',
                               description)


class SinkAdapter(object):

    engines = {
        'ddg': 'https://duckduckgo.com',
        'y': 'https://search.yahoo.com/search',
    }

    def __call__(self, req, resp, engine):
        url = self.engines[engine]
        params = {'q': req.get_param('q', True)}
        result = requests.get(url, params=params)

        resp.status = str(result.status_code) + ' ' + result.reason
        resp.content_type = result.headers['content-type']
        resp.body = result.text


class AuthMiddleware(object):

    def process_request(self, req, resp):
        token = req.get_header('X-Auth-Token')
        project = req.get_header('X-Project-ID')

        if token is None:
            description = ('Please provide an auth token '
                           'as part of the request.')

            raise falcon.HTTPUnauthorized('Auth token required',
                                          description,
                                          href='http://docs.example.com/auth')

        if not self._token_is_valid(token, project):
            description = ('The provided auth token is not valid. '
                           'Please request a new token and try again.')

            raise falcon.HTTPUnauthorized('Authentication required',
                                          description,
                                          href='http://docs.example.com/auth',
                                          scheme='Token; UUID')

    def _token_is_valid(self, token, project):
        config = ConfigParser.ConfigParser()
        config.read("general.config")
        solum_token = config.get("apinode", "token")
        if token == solum_token:
            return True  # Suuuuuure it's valid...
        else:
            return False


class RequireJSON(object):

    def process_request(self, req, resp):
        if not req.client_accepts_json:
            raise falcon.HTTPNotAcceptable(
                'This API only supports responses encoded as JSON.',
                href='http://docs.examples.com/api/json')

        if req.method in ('POST', 'PUT'):
            if 'application/json' not in req.content_type:
                raise falcon.HTTPUnsupportedMediaType(
                    'This API only supports requests encoded as JSON.',
                    href='http://docs.examples.com/api/json')


class JSONTranslator(object):

    def process_request(self, req, resp):
        # req.stream corresponds to the WSGI wsgi.input environ variable,
        # and allows you to read bytes from the request body.
        #
        # See also: PEP 3333
        if req.content_length in (None, 0):
            # Nothing to do
            return

        body = req.stream.read()
        if not body:
            raise falcon.HTTPBadRequest('Empty request body',
                                        'A valid JSON document is required.')

        try:
            req.context['doc'] = json.loads(body.decode('utf-8'))

        except (ValueError, UnicodeDecodeError):
            raise falcon.HTTPError(falcon.HTTP_753,
                                   'Malformed JSON',
                                   'Could not decode the request body. The '
                                   'JSON was incorrect or not encoded as '
                                   'UTF-8.')

    def process_response(self, req, resp, resource):
        if 'result' not in req.context:
            return

        resp.body = json.dumps(req.context['result'])


def max_body(limit):

    def hook(req, resp, resource, params):
        length = req.content_length
        if length is not None and length > limit:
            msg = ('The size of the request is too large. The body must not '
                   'exceed ' + str(limit) + ' bytes in length.')

            raise falcon.HTTPRequestEntityTooLarge(
                'Request body is too large', msg)

    return hook


class NessusScans(object):

    def __init__(self, db):
        self.db = db
        self.logger = my_logger

    def on_get(self, req, resp):
        marker = req.get_param('marker') or ''
        limit = req.get_param_as_int('limit') or 50

        try:

            result = self.db.get_scans()
        except Exception as ex:
            self.logger.error(ex)

            description = ('Aliens have attacked our base! We will '
                           'be back as soon as we fight them off. '
                           'We appreciate your patience.')

            raise falcon.HTTPServiceUnavailable(
                'Service Outage',
                description,
                30)

        # An alternative way of doing DRY serialization would be to
        # create a custom class that inherits from falcon.Request. This
        # class could, for example, have an additional 'doc' property
        # that would serialize to JSON under the covers.
        req.context['result'] = result

        resp.set_header('X-Powered-By', 'Small Furry Creatures')
        resp.status = falcon.HTTP_200

    @falcon.before(max_body(64 * 1024))
    def on_post(self, req, resp):
        try:
            doc = req.context['doc']
            my_logger.debug("POST data for scans:{}".format(doc))
        except KeyError:
            raise falcon.HTTPBadRequest(
                'Missing thing',
                'A thing must be submitted in the request body.')

        scan_id = self.db.add_scan(doc)

        resp.status = falcon.HTTP_201
        resp.location = '/scans/{}'.format(scan_id)


class NessusScan(object):

    def __init__(self, db):
        self.db = db
        self.logger = my_logger

    def on_get(self, req, resp, scan_id):
        marker = req.get_param('marker') or ''
        limit = req.get_param_as_int('limit') or 50

        try:
            result = self.db.get_scan_status(scan_id)
        except Exception as ex:
            self.logger.error(ex)

            description = ('Aliens have attacked our base! We will '
                           'be back as soon as we fight them off. '
                           'We appreciate your patience.')

            raise falcon.HTTPServiceUnavailable(
                'Service Outage',
                description,
                30)

        # An alternative way of doing DRY serialization would be to
        # create a custom class that inherits from falcon.Request. This
        # class could, for example, have an additional 'doc' property
        # that would serialize to JSON under the covers.
        req.context['result'] = result

        resp.set_header('X-Powered-By', 'Small Furry Creatures')
        resp.status = falcon.HTTP_200


# Configure your WSGI server to load "things.app" (app is a WSGI callable)
app = falcon.API(middleware=[
    AuthMiddleware(),
    RequireJSON(),
    JSONTranslator(),
])
my_logger.info("Create app")
db = ScanEngine()
scans = NessusScans(db)
scan = NessusScan(db)
my_logger.info("Adding route for the app")
app.add_route('/scans/{scan_id}', scan)
app.add_route('/scans', scans)


# Useful for debugging problems in your API; works with pdb.set_trace()
if __name__ == '__main__':
    httpd = simple_server.make_server('127.0.0.1', 8008, app)
    httpd.serve_forever()
