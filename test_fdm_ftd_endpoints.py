from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from requests.cookies import MockResponse

from fdm_ftd_endpoints import app, yaml_load, get_token, fdm_create_network_group

# Create a test client using the FastAPI app
client = TestClient(app)

test_yaml_file = "C:/Users/sumaya fathima/PycharmProjects/pythonProject/ftd_details.yml"
def test_yaml_load():
    yamldata = yaml_load(test_yaml_file)
    assert yamldata == {"devices": [
        {
            "username": 'ftd701',
            "password": 'Sbxftd1234!',
            "ipaddr": '192.168.1.1',
            "port": 443,
            "version": 1.0
        }
    ]}


def test_empty_yaml_file():
    yamldata = yaml_load(test_yaml_file)
    assert yamldata == None



#
# def test_access_token_saved_in_file(mocker, tmp_path):
#     mocker.patch('requests.post', return_value=Mock(status_code=200, json=lambda: {'access_token': 'test_token'}))
#     file_path = tmp_path / 'C:/Users/sumaya fathima/PycharmProjects/pythonProject/token.txt'
#     get_token('test_host')
#     assert file_path.read_text() == 'C:/Users/sumaya fathima/PycharmProjects/pythonProject/token.txt'
#
# @pytest.mark.asyncio
# async def test_successful_login(mocker):
#     mocker.patch('httpx.AsyncClient.post', return_value=Mock(status_code=200, json=Mock(return_value={'access_token': 'test_token'})))
#     mocker.patch('builtins.open', mocker.mock_open())
#     response = await get_token('test_host')
#     assert response == 'test_token'

async def test_successful_login():
    response = await get_token('192.168.1.1')
    assert response == 'abcd'
# def test_returns_json_response(self, mocker):
#     mocker.patch('requests.post', return_value=MockResponse(200, {'response': 'success'}))
#     result = fdm_create_network_group('test_host', 'test_token', 'test_version', {'payload': 'test_payload'})
#     assert isinstance(result, dict)