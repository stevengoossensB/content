import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from datetime import datetime, timedelta
import requests
import traceback
from typing import Dict, Any
import base64

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, verify, proxy, headers):
        self.page_size = 100
        self.date_format = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    ''' HELPER FUNCTIONS '''

    @staticmethod
    def get_cursor(timestamp):
        str_bytes = f'{timestamp}|'.encode('ascii')
        base64_bytes = base64.b64encode(str_bytes)
        return base64_bytes.decode('ascii')

    ''' COMMAND FUNCTIONS '''

    def get_logs(self, include: str, limit: int, after: datetime):
        logs = []

        params: Dict = {'include': include,
                        'order': 'asc',
                        'per_page': self.page_size}

        if after:
            params['after'] = self.get_cursor(after.timestamp() * 1000)

        res = self._http_request('GET', 'orgs/demisto/audit-log', params=params)

        if not res:
            return []

        if len(res) < self.page_size:
            return res[:limit]

        logs.extend(res)

        res_len = self.page_size

        # make request to get the logs until the logs count is less than the page size
        while self.page_size == res_len and len(logs) <= limit:
            # set the after parameter with the timestamp of the last log
            params['after'] = self.get_cursor(res[-1]['@timestamp'])
            res = self._http_request('GET', 'orgs/demisto/audit-log', params=params)
            res_len = len(res)

            # remove the last object because we will get it again in the next iteration
            res.pop(0)
            logs.extend(res)

        return logs[:limit]


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        client.get_logs(include='web', limit=10, after=datetime.utcnow() - timedelta(hours=1))
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Unauthorized' in str(e):
            message = 'Authorization Error: make sure API Token is correctly set'
        else:
            raise e
    return message


def get_logs_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    start_time = None

    # last_run = args.get('first_fetch')
    last_run = demisto.getLastRun().get('last_run')

    if last_run:
        start_time = datetime.strptime(last_run, client.date_format)
    logs = client.get_logs(args.get('include', 'web'), args.get('limit', 10000), start_time)

    if logs:
        last_time = logs[-1].get('@timestamp') / 1000
        next_fetch_time = datetime.fromtimestamp(last_time) + timedelta(seconds=1)
        last_time_str = next_fetch_time.strftime(client.date_format)
        demisto.setLastRun({'last_run': last_time_str})

    return CommandResults(
        outputs=logs
    )


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()

    token = params.get('credentials', {}).get('password')
    base_url = params.get('url', 'https://api.github.com')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: Dict = {'Accept': 'application/vnd.github.v3+json',
                         'Authorization': f'Bearer {token}'}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'GitHub-get-logs':
            return_results(get_logs_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
