import os
import httpx
from fastapi import FastAPI, HTTPException, Query
import requests
import json
import yaml
import uvicorn
import csv
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from crayons import blue, green, white, red, yellow, magenta, cyan
from pydantic import BaseModel, Field

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

app = FastAPI()


profile_filename = "C:/Users/sumaya fathima/PycharmProjects/pythonProject/ftd_details.yaml"
new_auth_token = ['none']  # global variable for storing the token
existing_name_list=[]
# system_network_object=["IPv4-Private-All-RFC1918","IPv4-Private-10.0.0.0-8","IPv4-Private-172.16.0.0-12","IPv4-Private-192.168.0.0-16","any-ipv4","any-ipv6"]

def yaml_load(profile_filename):
    fh = open(profile_filename, "r")
    yamlrawtext = fh.read()
    yamldata = yaml.load(yamlrawtext,Loader=yaml.FullLoader)
    return yamldata



def fdm_create_network_group(host,token,version,payload):
    '''
    This is a POST request to create a new network object in FDM.
    '''
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization":"Bearer {}".format(token)
    }
    try:
        api_url = "https://{}:{}/api/fdm/v{}/object/networkgroups".format(host, FDM_PORT, version)
        request = requests.post(api_url, json=payload,headers=headers, verify=False)
        return request.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to add network group")

# @app.get("/get_token",tags=['Token'])
# def get_token(ipaddr: str = Query(...)):
#         '''
#            This is the normal login which will give you a ~30 minute session with no refresh.
#            Should be fine for short lived work.
#            Do not use for sessions that need to last longer than 30 minutes.
#            '''
#         headers = {
#             "Content-Type": "application/json",
#             "Accept": "application/json",
#             "Authorization": "Bearer"
#         }
#         payload = {"grant_type": "password", "username": FDM_USER, "password": FDM_PASSWORD, "desired_expires_in": 31536000, "desired_refresh_expires_in": 34128000}
#
#         request = requests.get(f"https://{ipaddr}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/fdm/token",
#                                 json=payload, verify=False, headers=headers)
#         if request.status_code == 400:
#             raise Exception("Error logging in: {}".format(request.content))
#         # if request.status_code == 401:
#         #     print(red("Auth Token invalid, Let\'s ask for a new one", bold=True))
#         #     line_content = []
#         #     with open('C:/Users/sumayafathima.r/PycharmProjects/pythonProject2/FDM_Add_Security_Rules/token_FASTAPI.txt') as inputfile:
#         #         for line in inputfile:
#         #             if line.strip() != "":
#         #                 line_content.append(line.strip())
#         #     auth_token = line_content[0]
#         #     # headers["Authorization"]="Bearer {}".format(auth_token)
#         #     headers = {
#         #         "Content-Type": "application/json",
#         #         "Accept": "application/json",
#         #         "Authorization": "Bearer {}".format(auth_token)
#         #     }
#         #     api_url = f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/fdm/token"
#         #     request = requests.get(api_url, verify=False, headers=headers)
#         try:
#             access_token = request.json()['access_token']
#             fa = open("C:/Users/sumayafathima.r/PycharmProjects/pythonProject2/FDM_Add_Security_Rules/TOKEN.txt", "w")
#             fa.write(access_token)
#             fa.close()
#             new_auth_token[0] = access_token
#             print(green("Token = " + access_token))
#             print("Saved into TOKEN.txt file")
#             return access_token
#
#         except:
#             raise
class TokenManager:
    @staticmethod
    def set_token(token):
        # Implement token management logic here
        pass

@app.post("/get_token",tags=['Token'])
async def get_token(host):
    '''
    This is the normal login which will give you a ~30 minute session with no refresh.
    Should be fine for short lived work.
    Do not use for sessions that need to last longer than 30 minutes.
    '''
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer"
    }
    payload = {"grant_type": "password", "username": FDM_USER, "password": FDM_PASSWORD}

    async with httpx.AsyncClient() as client:
        response = await client.post(f"https://{host}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/fdm/token",
                                     json=payload, verify=False, headers=headers)
    if response.status_code == 400:
        raise Exception("Error logging in: {}".format(response.content))
    try:
        access_token = response.json()['access_token']
        file_path = os.environ.get('TOKEN_FILE_PATH')
        if not file_path:
            raise Exception('Token file path not found in environment variables')

        with open(file_path, 'w') as fa:
            fa.write(access_token)

        TokenManager.set_token(access_token)
        print(green("Token = " + access_token))
        print("Saved into token.txt file")
        return access_token
    except KeyError as e:
        raise Exception(f'Error accessing JSON: {e}')


@app.get("/get_hostname")
def get_hostname(ipaddr: str = Query(...)):
    token = new_auth_token[0]  # Access the global token variable
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    try:
        request = requests.get(
            f"https://{ipaddr}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/devicesettings/default/devicehostnames",
            verify=False,
            headers=headers,
        )
        return request.json()
    except:
       raise HTTPException(status_code=500, detail="Failed to get hostname")


""" NETWORK OBJECTS  """


@app.get("/object/networks",tags=['NetworkObject'])
def get_network_objects(offset: int = Query(0), limit: int = Query(1000)):
    # offset = input("Enter the offset value: ")
    # limit_global = input("Enter the limit value: ")
    token = new_auth_token[0]
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    try:
        request = requests.get(
            f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/networks?offset={offset}&limit={limit}",
            verify=False,
            headers=headers,
        )
        return request.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to get network object")

@app.get("/objects/networks/",tags=['NetworkObject'])
def get_object_id(object_id : str):

    headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            }
    # Replace with your Cisco FDM API endpoint and authentication details
    api_endpoint = f"https://{FDM_HOST}/api/fdm/v{FDM_VERSION}/object/networks/{object_id}"

    # Make the API call to add the network object
    response = requests.get(api_endpoint, verify=False,headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        # Network object added successfully
        return response.json()
    else:
        # Failed to add network object, raise HTTPException with the error message
        error_message = response.json().get("error", "Failed to add network object")
        raise HTTPException(status_code=response.status_code, detail=error_message)

@app.post("/object/networks",tags=['NetworkObject'])
def add_network_object(ipaddr:str, network_object: dict):
    headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            }
    # Replace with your Cisco FDM API endpoint and authentication details
    api_endpoint = f"https://{ipaddr}/api/fdm/v{FDM_VERSION}/object/networks"

    # Make the API call to add the network object
    post_add = requests.post(api_endpoint, json=network_object, verify=False,headers=headers)

    # Check if the request was successful
    if post_add.status_code == 201:
        # Network object added successfully
        return {"message": "Network object added successfully"}
    else:
        # Failed to add network object, raise HTTPException with the error message
        error_message = post_add.json().get("error", "Failed to add network object")
        raise HTTPException(status_code=post_add.status_code, detail=error_message)


@app.put(f"/object/networks",tags=['NetworkObject'])
def update_network_object(object_id: str,payload:str):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    try:
        request = requests.put(
            f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/networks/{object_id}",
            json=payload,
            verify=False,
            headers=headers,
        )
        return request.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to update network object")


@app.delete("/object/networks",tags=['NetworkObject'])
def delete_network_object(object_id:str):
    '''
      Delete every network object from the csv file
      '''
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    try:
        request = requests.delete(
            f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/networks/{object_id}",
            headers=headers, verify=False)
        return request.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to delete network object")



@app.post("/object/networkgroups",tags=['NetworkObject'])
def add_network_groups(ipaddr: str,network_object: dict):
    token = new_auth_token[0]
    network_group = fdm_create_network_group(ipaddr, token, FDM_VERSION,network_object)
    return network_group
@app.get("/object/networkgroups",tags=['NetworkObject'])
def get_network_object_group(ipaddr:str):
    token = new_auth_token[0]
    headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                }
    # Make the API call to retrieve the network object group
    response = requests.get(f"https://{ipaddr}/api/fdm/v{FDM_VERSION}/object/networkgroups", verify=False,headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        # Network object group retrieved successfully
        return response.json()
    else:
        # Failed to retrieve network object group, raise an exception with the error message
        error_message = response.json().get("error", "Failed to retrieve network object group")
        raise Exception(error_message)

@app.get("/object/networkgroups/{group_id}",tags=['NetworkObject'])
def get_network_object_group(group_id: str):
    token = new_auth_token[0]
    headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                }
    # Make the API call to retrieve the network object group
    response = requests.get(f"https://{FDM_HOST}/api/fdm/v{FDM_VERSION}/object/networkgroups/{group_id}", verify=False,headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        # Network object group retrieved successfully
        return response.json()
    else:
        # Failed to retrieve network object group, raise an exception with the error message
        error_message = response.json().get("error", "Failed to retrieve network object group")
        raise Exception(error_message)

@app.put("/object/networkgroups/{group_id}",tags=['NetworkObject'])
def get_network_object_group(group_id: str,updated_object:dict):
    token = new_auth_token[0]
    headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                }
    # Make the API call to retrieve the network object group
    response = requests.put(f"https://{FDM_HOST}/api/fdm/v{FDM_VERSION}/object/networkgroups/{group_id}", json=updated_object,verify=False,headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        # Network object group retrieved successfully
        return response.json()
    else:
        # Failed to retrieve network object group, raise an exception with the error message
        error_message = response.json().get("error", "Failed to retrieve network object group")
        raise Exception(error_message)

@app.delete("/object/networkgroups/{group_id}",tags=['NetworkObject'])
def get_network_object_group(group_id: str):
    token = new_auth_token[0]
    headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                }
    # Make the API call to retrieve the network object group
    response = requests.delete(f"https://{FDM_HOST}/api/fdm/v{FDM_VERSION}/object/networkgroups/{group_id}", verify=False,headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        # Network object group retrieved successfully
        return response.json()
    else:
        # Failed to retrieve network object group, raise an exception with the error message
        error_message = response.json().get("error", "Failed to retrieve network object group")
        raise Exception(error_message)

""" ACCESS POLICY"""


@app.get("/policy/accesspolicies",tags=['AccessPolicy'])
def get_policy(ipaddr:str,offset: int = Query(...), limit: int = Query(...)):
    token = new_auth_token[0]
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    try:
        request = requests.get(
            f"https://{ipaddr}:{FDM_PORT}//api/fdm/v{FDM_VERSION}/policy/accesspolicies?offset={offset}&limit={limit}",
            verify=False,
            headers=headers,
        )
        return request.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to get access policy ")


@app.get("/policy/accesspolicies/{objid}",tags=['AccessPolicy'])
def get_policy(ipaddr:str,objid:str):
    token = new_auth_token[0]
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    try:
        request = requests.get(
            f"https://{ipaddr}:{FDM_PORT}//api/fdm/v{FDM_VERSION}/policy/accesspolicies/{objid}",
            verify=False,
            headers=headers,
        )
        return request.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to get access policy ")

@app.put("/policy/accesspolicies/{objid}",tags=['AccessPolicy'])
def get_policy(ipaddr:str,objid:str):
    token = new_auth_token[0]
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    try:
        request = requests.put(
            f"https://{ipaddr}:{FDM_PORT}//api/fdm/v{FDM_VERSION}/policy/accesspolicies/{objid}",
            verify=False,
            headers=headers,
        )
        return request.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to get access policy ")


@app.get("/policy/accesspolicies/{parent_id}/accessrules",tags=['AccessPolicy'])
def fdm_get_access_rule(parent_id:str):
    '''
    This is a POST request to create a new access list.
    '''
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization":"Bearer {}".format(token)
    }
    try:
        get_rule = requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/accesspolicies/{parent_id}/accessrules",
                       headers=headers, verify=False)
        return get_rule.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to add access rule")




@app.post("/policy/accesspolicies/{parent_id}/accessrules",tags=['AccessPolicy'])
def fdm_create_access_rule(parent_id:str,access_rule:dict):
    '''
    This is a POST request to create a new access list.
    '''
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization":"Bearer {}".format(token)
    }
    payload = {
        "name": access_rule.get("name"),
        "ruleAction": access_rule.get("ruleAction"),
        "sourceNetworks": access_rule.get("sourceNetworks"),
        "destinationNetworks": access_rule.get("destinationNetworks"),
        # Add other properties of the access rule payload as needed
    }
    try:
        add_rule = requests.post(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/accesspolicies/{parent_id}/accessrules",
                    json=payload, headers=headers, verify=False)
        return add_rule.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to add access rule")


@app.put("/policy/accesspolicies/{parent_id}/accessrules/{object_id}",tags=['AccessPolicy'])
def fdm_update_access_rule(parent_id:str,object_id:str,payload:dict):
    '''
    This is a POST request to create a new access list.
    '''
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization":"Bearer {}".format(token)
    }
    try:
        update_rule = requests.put(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/accesspolicies/{parent_id}/accessrules/{object_id}",
                    json=payload, headers=headers, verify=False)
        return update_rule.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to add access rule")


@app.delete("/policy/accesspolicies/{parent_id}/accessrules/{object_id}",tags=['AccessPolicy'])
def fdm_delete_access_rule(parent_id:str,object_id:str):
    '''
    This is a POST request to create a new access list.
    '''
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization":"Bearer {}".format(token)
    }
    try:
        delete_rule = requests.delete(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/accesspolicies/{parent_id}/accessrules/{object_id}",
                     headers=headers, verify=False)
        return delete_rule.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to delete access rule")




""" PORT OBJECT  """


@app.get("/object/tcpports",tags=['PortObject'])
def get_tcports(ipaddr:str, offset: int = Query(...), limit: int = Query(...)):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    response = requests.get(f"https://{ipaddr}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/tcpports?offset={offset}&limit={limit}",
                            headers=headers,verify=False)
    return response.json()


@app.get("/objects/{param}",tags=['PortObject'])
def get_services(param:str,offset: int = Query(...), limit: int = Query(...)):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    # get Port Object Groups
    if param == "tcp":
        api_path="/object/tcpports"
        services2 = requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/{api_path}?offset={offset}&limit={limit}",headers=headers,verify=False)
        return services2.json()
    elif param == "udp":
        api_path="/object/udpports"
        services3 = requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/{api_path}?offset={offset}&limit={limit}",headers=headers,verify=False)
        return services3.json()
    elif param == 'protocols':
        protocols = requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/protocols?offset={offset}&limit={limit}",
                                       headers=headers, verify=False)
        return protocols.json()
    elif param == 'icmpv4':
        icmpv4 = requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/icmpv4ports?offset={offset}&limit={limit}",
                                    headers=headers, verify=False)
        return icmpv4.json()
    elif param == 'icmpv6':
        icmpv6 = requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/icmpv6ports?offset={offset}&limit={limit}",
                                    headers=headers, verify=False)
        return icmpv6.json()
    elif param == "portgroups":
        api_path = "/object/portgroups"
        services1 = requests.get(
            f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/{api_path}?offset={offset}&limit={limit}",
            headers=headers, verify=False)
        return services1.json()


@app.post("/object/{ports}",tags=['PortObject'])
def fdm_create_service(ports:str,payload:dict):
    '''
    This is a POST request take paylaod as the URL API to invoke.
    '''
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    try:
        if ports == 'tcp':
            add_tcpport = requests.post(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/tcpports",
                                        json=payload, headers=headers, verify=False)
            return add_tcpport.json()
        elif ports == 'udp':
            add_udpport = requests.post(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/udpports",
                                        json=payload, headers=headers, verify=False)
            return add_udpport.json()
        elif ports == 'protocols':
            add_protocols = requests.post(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/protocols",
                                          json=payload, headers=headers, verify=False)
            return add_protocols.json()
        elif ports == 'icmpv4':
            add_icmpv4 = requests.post(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/icmpv4ports",
                                       json=payload, headers=headers, verify=False)
            return add_icmpv4.json()
        elif ports == 'icmpv6':
            add_icmpv6 = requests.post(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/icmpv6ports",
                                       json=payload, headers=headers, verify=False)
            return add_icmpv6.json()
        elif ports == 'portgroups':
            portgroups = requests.post(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/portgroups",
                                       json=payload, headers=headers, verify=False)
            return portgroups.json()
    except:
        raise  HTTPException(status_code=500, detail="Failed to add tcp ports")

@app.put("/object/ports/{objid}",tags=['PortObject'])
def fdm_update_service(ports:str,payload:dict,objid:str):
    '''
    This is a POST request take paylaod as the URL API to invoke.
    '''
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    try:
        if ports == 'tcp':
            update_tcpport = requests.put(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/tcpports/{objid}", json=payload, headers=headers, verify=False)
            return update_tcpport.json()
        elif ports == 'udp':
            update_udpport = requests.put(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/udpports/{objid}", json=payload, headers=headers, verify=False)
            return update_udpport.json()
        elif ports == 'protocols':
            update_protocols = requests.put(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/protocols", json=payload, headers=headers, verify=False)
            return update_protocols.json()
        elif ports == 'icmpv4':
            update_icmpv4 = requests.put(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/icmpv4ports/{objid}", json=payload, headers=headers, verify=False)
            return update_icmpv4.json()
        elif ports == 'icmpv6':
            update_icmpv6 = requests.put(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/icmpv6ports/{objid}", json=payload, headers=headers, verify=False)
            return update_icmpv6.json()
        elif ports == 'portgroups':
            portgroups = requests.put(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/portgroups", json=payload, headers=headers, verify=False)
            return portgroups.json()
    except:
        raise  HTTPException(status_code=500, detail="Failed to add tcp ports")

@app.delete("/object/ports/{objid}",tags=['PortObject'])
def fdm_delete_service(ports:str,objid:str):
    '''
    This is a POST request take paylaod as the URL API to invoke.
    '''
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    try:
        if ports == 'tcp':
            delete_tcpport = requests.delete(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/tcpports/{objid}",  headers=headers, verify=False)
            return delete_tcpport.json()
        elif ports == 'udp':
            delete_udpport = requests.delete(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/udpports/{objid}",  headers=headers, verify=False)
            return delete_udpport.json()
        elif ports == 'protocols':
            delete_protocols = requests.delete(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/protocols",  headers=headers, verify=False)
            return delete_protocols.json()
        elif ports == 'icmpv4':
            delete_icmpv4 = requests.delete(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/icmpv4ports/{objid}", headers=headers, verify=False)
            return delete_icmpv4.json()
        elif ports == 'icmpv6':
            delete_icmpv6 = requests.delete(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/icmpv6ports/{objid}", headers=headers, verify=False)
            return delete_icmpv6.json()
        elif ports == 'portgroups':
            portgroups = requests.delete(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/portgroups",  headers=headers, verify=False)
            return portgroups.json()
    except:
        raise  HTTPException(status_code=500, detail="Failed to add tcp ports")






""" SECURITY ZONE  """


@app.get("/object/securityzones",tags=['SecurityZone'])
def get_securityzone(ipaddr:str, offset: int = Query(...), limit: int = Query(...)):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    get_security = requests.get(f"https://{ipaddr}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/securityzones?offset={offset}&limit={limit}",
                            headers=headers,verify=False)
    return get_security.json()



@app.post("/object/securityzones",tags=['SecurityZone'])
def add_securityzone(ipaddr:str,payload:dict):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    add_zone = requests.post(f"https://{ipaddr}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/securityzones",
                            json=payload,headers=headers,verify=False)
    return add_zone.json()

@app.get("/object/securityzones/{objid}",tags=['SecurityZone'])
def get_securityzone_objid(ipaddr:str,objid:str):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    securityzone = requests.get(f"https://{ipaddr}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/securityzones/{objid}",
                            headers=headers,verify=False)
    return securityzone.json()

@app.put("/object/securityzones/{objid}",tags=['SecurityZone'])
def add_securityzone_objid(ipaddr:str,objid:str,payload:str):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    add_securityzone_obj = requests.put(f"https://{ipaddr}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/object/securityzones/{objid}",
                            json=payload,headers=headers,verify=False)
    return add_securityzone_obj.json()





""" INTERFACES """


@app.get("/default/interfaces",tags=['Interfaces'])
def get_interfaces(ipaddr:str):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    get_interface = requests.get(f"https://{ipaddr}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/devices/default/interfaces",
                            headers=headers,verify=False)
    return get_interface.json()


@app.get("/interfaces/{objid}",tags=['Interfaces'])
def get_interfaces(ipaddr:str,objid:str):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    get_interface = requests.get(f"https://{ipaddr}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/devices/default/operational/interfaces/{objid}",
                            headers=headers,verify=False)
    return get_interface.json()




""" NAT """

""" NAT - OBJECT RULE """

@app.get("/policy/objectnatpolicies",tags=['NAT'])
def objectnatpolicies():
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    objectnat = requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/objectnatpolicies",
                            headers=headers,verify=False)
    return objectnat.json()


@app.get("/policy/objectnatpolicies/{objid}",tags=['NAT'])
def objectnatpolicies_obj(objid:str):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    objectnat = requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/objectnatpolicies/{objid}",
                            headers=headers,verify=False)
    return objectnat.json()

@app.get("/policy/objectnatpolicies/{parentid}/objectnatrules",tags=['NAT'])
def fdm_objectnatrules(parentid:str):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    objectnatrules= requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/objectnatpolicies/{parentid}/objectnatrules",
                            headers=headers,verify=False)
    return objectnatrules.json()


class ManualNatRulePayload(BaseModel):
    version: str
    name: str
    description: str
    sourceInterface: dict
    destinationInterface: dict
    natType: str
    patOptions: dict
    netToNet: bool
    noProxyArp: bool
    dns: bool
    interfaceIPv6: bool
    routeLookup: bool
    enabled: bool
    originalNetwork: dict
    translatedNetwork: dict
    originalPort: dict
    translatedPort: dict
    interfaceInTranslatedNetwork: bool
    rulePosition: int
    id: str
    type: str

@app.post("/policy/objectnatpolicies/{parentid}/objectnatrules",tags=['NAT'])
def fdm_add_objectnatrules(parentid:str, payload:ManualNatRulePayload):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    add_objectnatrules= requests.post(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/objectnatpolicies/{parentid}/objectnatrules",
                            json=payload,headers=headers,verify=False)
    return add_objectnatrules.json()

@app.get("/policy/objectnatpolicies/{parentid}/objectnatrules/{objid}",tags=['NAT'])
def objectnatrules_obj(parentid:str,objid:str):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    objectnatrules= requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/objectnatpolicies/{parentid}/objectnatrules/{objid}",
                            headers=headers,verify=False)
    return objectnatrules.json()

@app.put("/policy/objectnatpolicies/{parentid}/objectnatrules/{objid}",tags=['NAT'])
def fdm_update_objectnatrules(parentid:str,objid:str,payload:dict):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    update_objectnatrules= requests.put(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/objectnatpolicies/{parentid}/objectnatrules/{objid}",
                            json=payload,headers=headers,verify=False)
    return update_objectnatrules.json()

@app.delete("/policy/objectnatpolicies/{parentid}/objectnatrules/{objid}",tags=['NAT'])
def fdm_delete_objectnatrules(parentid:str,objid:str):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    delete_objectnatrules= requests.delete(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/objectnatpolicies/{parentid}/objectnatrules/{objid}",
                            headers=headers,verify=False)
    return delete_objectnatrules.json()




""" NAT - MANUAL NAT """

@app.get("/policy/manualnatpolicies",tags=['NAT'])
def manualnatpolicies():
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    manualnatpolicies = requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/manualnatpolicies",
                            headers=headers,verify=False)
    return manualnatpolicies.json()


@app.get("/policy/manualnatpolicies/{parentid}/manualnatrules",tags=['NAT'])
def fdm_get_manualnatrule(parentid:str):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    manualnatrule = requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/manualnatpolicies/{parentid}/manualnatrules",
                            headers=headers,verify=False)
    return manualnatrule.json()


@app.post("/policy/manualnatpolicies/{parentid}/manualnatrules",tags=['NAT'])
def fdm_create_manualnatrule(parentid:str,payload:dict):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    add_manualnatrule = requests.post(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/manualnatpolicies/{parentid}/manualnatrules",
                            json=payload,headers=headers,verify=False)
    return add_manualnatrule.json()

@app.get("/policy/manualnatpolicies/{parentid}/manualnatrules/{objid}",tags=['NAT'])
def fdm_get_manualnatrule(parentid:str,objid:str,payload:dict):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    get_manualnatrule = requests.get(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/manualnatpolicies/{parentid}/manualnatrules/{objid}",
                            json=payload,headers=headers,verify=False)
    return get_manualnatrule.json()

@app.put("/policy/manualnatpolicies/{parentid}/manualnatrules/{objid}",tags=['NAT'])
def fdm_update_manualnatrule(parentid:str,objid:str,payload:dict):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    update_manualnatrule = requests.put(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/manualnatpolicies/{parentid}/manualnatrules/{objid}",
                            json=payload,headers=headers,verify=False)
    return update_manualnatrule.json()

@app.delete("/policy/manualnatpolicies/{parentid}/manualnatrules/{objid}",tags=['NAT'])
def fdm_delete_manualnatrule(parentid:str,objid:str,payload:dict):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(token)
    }
    delete_manualnatrule = requests.delete(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/policy/manualnatpolicies/{parentid}/manualnatrules/{objid}",
                            json=payload,headers=headers,verify=False)
    return delete_manualnatrule.json()




@app.post("/operational/deploy",tags=['Deploy'])
def deploy():
    '''
    This is a POST request to create a new network object in FDM.
    '''
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization":"Bearer {}".format(token)
    }
    try:
        request = requests.post(f"https://{FDM_HOST}:{FDM_PORT}/api/fdm/v{FDM_VERSION}/operational/deploy",headers=headers, verify=False)
        return request.json()
    except:
        raise






if __name__ == "__main__":
    ftd_host = {}
    ftd_host = yaml_load(profile_filename)
    print(ftd_host["devices"])
    FDM_USER = ftd_host["devices"][0]['username']
    FDM_PASSWORD = ftd_host["devices"][0]['password']
    FDM_HOST = ftd_host["devices"][0]['ipaddr']
    FDM_PORT = ftd_host["devices"][0]['port']
    FDM_VERSION = ftd_host["devices"][0]['version']    
    fa = open("C:/Users/sumayafathima.r/PycharmProjects/pythonProject2/FDM_Add_Security_Rules/TOKEN.txt", "r")
    token = fa.readline()
    fa.close()
    new_auth_token[0] = token
    uvicorn.run(app, host="127.0.0.1", port=8000)