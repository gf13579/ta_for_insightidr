import datetime
import getpass
import requests
import re
import html
import sys
from loguru import logger
import pyotp
import time
import json


def get_usage_stats(
    session, org_id, customer_name, fqdn="au.rest.logs.insight.rapid7.com"
):
    """
    Retrieves the usage statistics for an organization from the Rapid7 Insight platform.

    Args:
        session (object): The session object used for making HTTP requests.
        org_id (str): The ID of the organization.
        customer_name (str): The name of the customer.
        fqdn (str, optional): The fully qualified domain name of the Rapid7 Insight platform. Defaults to "au.rest.logs.insight.rapid7.com".

    Returns:
        dict: A dictionary containing the usage statistics data and metadata.
    """
    # declare 'from' and 'to' params based on today's date (to) and the first of the month 12 months ago

    params = {
        "from": (datetime.datetime.now() - datetime.timedelta(days=365))
        .replace(day=1)
        .strftime("%Y-%m-%d"),
        "to": datetime.datetime.now().strftime("%Y-%m-%d"),
    }

    response = session.get(f"https://{fqdn}/usage/organizations", params=params)

    data = response.json()

    metadata = {
        "org_id": org_id,
        "customer_name": customer_name,
        "query": "get_usage_stats",
    }
    return {"data": data, "metadata": metadata}


def get_event_collection_status(
    session, org_id, customer_name, fqdn="au.razor.insight.rapid7.com"
):
    """
    Retrieves the event collection status for a given organization and customer.

    Args:
        session (object): The session object used for making HTTP requests.
        org_id (str): The ID of the organization.
        customer_name (str): The name of the customer.
        fqdn (str, optional): The fully qualified domain name. Defaults to "au.razor.insight.rapid7.com".

    Returns:
        dict: A dictionary containing the event collection data and metadata.
            The "data" key holds the event collection data.
            The "metadata" key holds the metadata information, including the org_id, customer_name, and query.
    """
    data = []

    params = {
        "index": "0",
        "size": "20",
        "name": "",
    }

    # loop up to 50 times (assuming we have no more than 1000 event sources to check for)
    for i in range(50):
        params["index"] = str(i)
        response = session.get(f"https://{fqdn}/api/3/eventsources", params=params)

        try:
            # Remove random XSS protection rubbish from the response
            response_text = re.sub(r'^.*{"data"', '{"data"', response.text)
            response_json = json.loads(response_text)

            if "data" in response_json:
                data.extend(response_json["data"])
        except Exception as e:
            logger.error(
                f"Error getting event collection status: {response.status_code} {response.text}. {str(e)}"
            )

        # exit loop if no more data
        if response_json["metadata"]["size"] == 0:
            break
        logger.info(
            'Looping on get_event_collection_status query. data["metadata"]["size"] is '
            + str(response_json["metadata"]["size"])
        )
        time.sleep(0.5)

    metadata = {
        "org_id": org_id,
        "customer_name": customer_name,
        "query": "get_event_collection_status",
    }

    return {"data": data, "metadata": metadata}


def get_user_product_access(session, org_id, customer_name, fqdn="insight.rapid7.com"):
    """
    Retrieves the product access for a user from the Rapid7 Insight platform.

    Args:
        session (requests.Session): The session object used for making HTTP requests.
        org_id (str): The organization ID.
        customer_name (str): The name of the customer.
        fqdn (str, optional): The fully qualified domain name of the Insight platform. Defaults to "insight.rapid7.com".

    Returns:
        dict: A dictionary containing the response JSON data and metadata. If an error occurs, an empty dictionary is returned.
    """
    response = session.get(f"https://{fqdn}/api/2/user/all/productAccess")
    if response.status_code == 202:
        time.sleep(5)
        response = session.get(f"https://{fqdn}/api/2/user/all/productAccess")
    try:
        response_json = {"data": response.json()}
        metadata = {
            "org_id": org_id,
            "customer_name": customer_name,
            "query": "get_user_product_access",
        }
        response_json["metadata"] = metadata
        return response_json
    except Exception as e:
        logger.error(f"Error getting user product access: {str(e)}")
        return {}
    return {}


def get_detections(
    session, org_id, customer_name, fqdn="au.rest.logs.insight.rapid7.com"
):
    """
    Retrieves detections from the Rapid7 InsightIDR API.

    Args:
        session (requests.Session): The session object for making HTTP requests.
        org_id (str): The organization ID.
        customer_name (str): The name of the customer.
        fqdn (str, optional): The fully qualified domain name of the API endpoint. Defaults to "au.rest.logs.insight.rapid7.com".

    Returns:
        dict: The response JSON containing the detections.

    """
    response = session.get(f"https://{fqdn}/management/tags")
    response_json = response.json()

    metadata = {
        "org_id": org_id,
        "customer_name": customer_name,
        "query": "get_detections",
    }

    response_json["metadata"] = metadata
    return response_json


def get_asset_counts(
    session, org_id, customer_name, fqdn="au.query.datacollection.insight.rapid7.com"
):
    """
    Retrieves asset counts for a given organization.

    Args:
        session (object): The session object used for making HTTP requests.
        org_id (str): The ID of the organization.
        customer_name (str): The name of the customer.
        fqdn (str, optional): The fully qualified domain name. Defaults to "au.query.datacollection.insight.rapid7.com".

    Returns:
        dict: The response JSON containing asset counts and metadata.
    """
    query = "query GetAssetCounts($orgId: String!) {\n  organization(id: $orgId) {\n    retention {\n      retentionPeriod\n      __typename\n    }\n    metrics {\n      agents {\n        status {\n          online\n          offline\n          stale\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}"
    response = session.post(
        url=f"https://{fqdn}/v1/guardian/graphql",
        json={
            "operationName": "GetAssetCounts",
            "variables": {"orgId": org_id},
            "query": query,
        },
    )
    response_json = response.json()

    metadata = {
        "org_id": org_id,
        "customer_name": customer_name,
        "query": "get_asset_counts",
    }
    response_json["metadata"] = metadata
    return response_json


def auth_via_okta(
    username,
    password,
    otp_secret,
    okta_host="rapid7ipimseu.okta-emea.com",
    proxies={},
):
    """
    Authenticate with Rapid7 via Okta with a non-SSO account.

    Args:
        username (str): The username for authentication.
        password (str): The password for authentication.
        otp_secret (str): The secret for one-time password (OTP) authentication.
        okta_host (str, optional): The Okta host URL. Defaults to "rapid7ipimseu.okta-emea.com".
        proxies (dict, optional): The proxy settings. Defaults to {}.

    Returns:
        requests.Session: The authenticated session object.

    Raises:
        Exception: If there is an error during authentication.
    """
    # This function authenticates with Rapid7 via Okta with a non-SSO account
    # The resultant cookies can be used to make queries against InsightIDR's underlying APIs to retrieve information not exposed through the public, documented APIs

    # Overview
    #
    # - We're after an IPIMS_WEB_SESSION cookie and possibly an updated IPIMS_SESSION cookie (set pre-login)
    # - We have to do a SAML dance with Okta: rapid7ipimseu.okta-emea.com
    # - Most of the magic happens through automatic (302) redirections handled by the requests library after our POST with the username and password
    # - We finish by getting a SAMLResponse and RelayState value from Okta and posting that to https://insight.rapid7.com/saml/SSO
    # - The code also does an OTP exchange with Okta i.e. MFA
    # - We also need to get a CSRF token from the response to the last POST and include that in future requests

    session = requests.Session()
    session.proxies = proxies
    # session.verify = False

    # --- Step 1: Hit the login page and get the loginUrl from the response

    response = session.get("https://insight.rapid7.com/login")

    # read the value of loginUrl from the config json object mentioned in javascript included in the response
    login_url = ""
    try:
        login_url = re.findall(r'loginUrl: "([^"]+)"', response.text, flags=re.DOTALL)[
            0
        ]
        login_url = login_url.replace("\\", "")

    except Exception as e:
        print(f"Unable to parse config json from response {str(e)}", file=sys.stderr)
        exit()

    # --- Step 2: Post username/password to api/v1/authn and get the stateToken and factorId from the response

    headers = {
        "Accept": "*/*",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-okta-user-agent-extended",
        "Origin": "https://insight.rapid7.com",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Dest": "empty",
    }

    session.headers.update(headers)

    json_data = {
        "password": password,
        "username": username,
        "options": {
            "warnBeforePasswordExpired": True,
            "multiOptionalFactorEnroll": True,
        },
    }

    session.options(url=f"https://{okta_host}/api/v1/authn")
    response = session.post(url=f"https://{okta_host}/api/v1/authn", json=json_data)

    logger.debug(f"response.status_code: {response.status_code}")
    # logger.debug(f"response.text: {response.text}")

    state_token = ""
    factor_id = ""
    try:
        response_json = response.json()
        state_token = response_json["stateToken"]
        factor_id = response_json["_embedded"]["factors"][0]["id"]
    except Exception as e:
        logger.info(
            f"Unable to parse stateToken and factorId from response {str(e)}",
            file=sys.stderr,
        )

    # --- Step 3: Post the OTP to api/v1/authn/factors/{factorId}/verify and get the session_token from the response

    headers = {
        "Host": "rapid7ipimseu.okta-emea.com",
        "X-Okta-User-Agent-Extended": "okta-auth-js/5.8.0 okta-signin-widget-5.14.1",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://insight.rapid7.com",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
    }

    session.headers.update(headers)

    params = {
        "rememberDevice": "false",
    }

    json_data = {
        "passCode": pyotp.TOTP(otp_secret).now(),
        "stateToken": state_token,
    }

    response = session.options(
        f"https://{okta_host}/api/v1/authn/factors/{factor_id}/verify",
        params=params,
    )

    response = session.post(
        f"https://{okta_host}/api/v1/authn/factors/{factor_id}/verify",
        params=params,
        json=json_data,
    )

    session_token = ""
    try:
        response_json = response.json()
        session_token = response_json["sessionToken"]
    except Exception as e:
        logger.info(
            f"Unable to parse sessionToken from response {str(e)}", file=sys.stderr
        )

    # --- Step 4: Hit the login/sessionCookieRedirect page and get the SAMLResponse and RelayState from the response

    params = {
        "checkAccountSetupComplete": "true",
        "token": session_token,
        "redirectUrl": login_url,
    }

    response = session.get(
        f"https://{okta_host}/login/sessionCookieRedirect",
        params=params,
        allow_redirects=True,
    )

    saml_response = ""
    relay_state = ""
    try:
        saml_response = re.findall(
            r'name="SAMLResponse" type="hidden" value="([^"]+)"',
            response.text,
            flags=re.DOTALL,
        )[0]
        saml_response = saml_response.replace("\\", "")
        relay_state = re.findall(
            r'name="RelayState" type="hidden" value="([^"]+)"',
            response.text,
            flags=re.DOTALL,
        )[0]
        relay_state = relay_state.replace("\\", "")

    except Exception as e:
        print(
            f"Unable to parse SAMLResponse and RelayState from response {str(e)}",
            file=sys.stderr,
        )
        exit()

    # --- Step 5: Post the SAMLResponse and RelayState to https://insight.rapid7.com/saml/SSO to get an updated IPIMS_WEB_SESSION cookie

    data = {
        "SAMLResponse": html.unescape(saml_response),
        "RelayState": html.unescape(relay_state),
    }

    headers = {
        "Host": "insight.rapid7.com",
        "Origin": f"https://{okta_host}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "Referer": f"https://{okta_host}/",
    }

    session.headers.update(headers)

    response = session.post(
        url="https://insight.rapid7.com/saml/SSO",
        data=data,
    )

    # We should have a IPIMS_WEB_SESSION from that last POST, and it redirects to '/platform?continue', which has a CSRF token we may need

    # parse the CSRF from the response
    csrf = None
    try:
        csrf = re.findall(
            r'<meta name="_csrf" content="([^"]+)"/>',
            response.text,
            flags=re.DOTALL,
        )[0]
    except Exception as e:
        logger.info(f"Unable to parse CSRF from response {str(e)}", file=sys.stderr)

    headers = {"X-Csrf-Token": csrf, "Csrftoken": csrf}
    session.headers.update(headers)

    return session


def switch_customer_by_name(session, customer_name):
    """
    Switches the customer in the session based on the provided customer name.

    Args:
        session (object): The session object used for making HTTP requests.
        customer_name (str): The name of the customer to switch to.

    Returns:
        str: The organization ID of the switched customer, or None if the customer was not found.
    """
    org_id = None

    # This next response may include customers but not our partner org as we're a partner not a customer.
    # You can see that our customer ID isn't displayed on the customer table (https://insight.rapid7.com/platform#/customer)

    response = session.get("https://insight.rapid7.com/api/1/user/customers")

    customer_id = None
    response_json = response.json()
    cust_list = [
        customer
        for customer in response_json
        if customer["name"].lower() == customer_name.lower()
    ]
    if len(cust_list) > 0:
        try:
            customer_id = cust_list[0]["customerId"]
            products = cust_list[0]["organizationAccessList"][0]
            product_token = [
                p["productToken"]
                for p in products["products"]
                if p["productName"] == "InsightIDR"
            ][0]
        except Exception as e:
            logger.error(
                f"Unable to parse customer ID and product token from response {str(e)}",
                file=sys.stderr,
            )
            return None
    else:
        return None

    params = {
        "customerId": customer_id,
    }

    headers = {
        "Accept": "application/json, text/plain, */*",
        "Origin": "https://insight.rapid7.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://insight.rapid7.com/platform?continue",
    }

    session.headers.update(headers)

    # This will result in an updated IPIMS_WEB_SESSION and future requests relating to the customer whose id we provide
    response = session.put(
        "https://insight.rapid7.com/api/1/me/session/customer",
        params=params,
    )

    # Let Host and Content-Type be set automatically in future requests
    headers_to_reset = ["Host", "Content-Type"]
    for header in headers_to_reset:
        if header in session.headers:
            session.headers.pop(header)

    org_id = get_org_id(session)

    new_headers = {
        "R7-Consumer": "idr-js",
        "R7-Organization-Id": org_id,
        "X-Orgproduct-Token": product_token,
        "R7-Organization-Product-Token": product_token,
    }

    session.headers.update(new_headers)

    return org_id


def get_org_id(session):
    """
    Retrieves the organization ID from the Rapid7 Insight IDR API.

    Args:
        session (requests.Session): The session object used for making HTTP requests.

    Returns:
        str: The organization ID, or None if no organization ID is found.
    """
    org_id = None
    response = session.get("https://insight.rapid7.com/api/1/organization/all")
    response_json = response.json()
    if len(response_json) > 0:
        org_id = response_json[0]["organizationId"]
    return org_id


def main():
    """
    Function that tests the module when you run the file as a script
    1. Sets up proxies for HTTP and HTTPS requests.
    2. Authenticates the user via Okta.
    3. Switches the customer by name.
    4. Retrieves various data for the specified customer.
    5. Prints the results.

    Note: Some lines of code are commented out for reference purposes.
    """

    proxies = {
        "http": "http://someproxy.local:8080",
        "https": "http://someproxy.local:8080",
    }
    # proxies = {}

    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    customer_name = input("Enter the customer name: ")

    session = auth_via_okta(
        username=username,
        password=password,
        otp_secret=getpass.getpass("Enter your OTP secret: "),
        proxies=proxies,
    )

    org_id = switch_customer_by_name(session, "TBD")
    # results = rapid7lib.get_asset_counts(session, org_id, customer_name=customer_name)
    # results = rapid7lib.get_detections(session, org_id, customer_name=customer_name)
    # results = rapid7lib.get_user_product_access(
    #     session, org_id, customer_name=customer_name
    # )
    results = get_event_collection_status(session, org_id, customer_name=customer_name)
    print(results)


if __name__ == "__main__":
    main()
