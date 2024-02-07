import json
import os
import sys
from loguru import logger
# import requests

# import splunklib.results as results
from requests.adapters import HTTPAdapter, Retry

import rapid7lib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(
    os.path.join(os.environ["SPLUNK_HOME"], "etc", "apps", "SA-VSCode", "bin")
)

from splunklib.modularinput import Scheme, Argument, Event, Script

try:
    import splunk_debug as dbg  # noqa: E402 "# type: ignore

    dbg.enable_debugging(timeout=10)
    dbg.set_breakpoint()
except ImportError as error:
    print("Failed to import splunk_debug", file=sys.stderr)
    print("Error" + str(error), file=sys.stderr)

log_file = os.environ["SPLUNK_HOME"] + "/var/log/splunk/ta_for_insightidr.log"
logger.remove()
logger.add(sink=log_file, level="INFO")
logger.add(sink=sys.stderr, level="ERROR")

# for development
logger.add(sink=log_file, level="DEBUG")


def flatten_list(list_of_lists):
    return [item for sublist in list_of_lists for item in sublist]


class MyScript(Script):
    def get_scheme(self):
        """ "InsightIDR Input" is the name Splunk will display to users for this input."""
        scheme = Scheme("InsightIDR Input")

        scheme.description = (
            "Authenticates to Rapid7 via Okta and queries the InsightIDR web site APIs "
        )
        scheme.use_external_validation = False

        # Set to false so each input can have an optional interval parameter
        scheme.use_single_instance = False

        customer_name_argument = Argument("customer_names")
        customer_name_argument.title = "Customer Names"
        customer_name_argument.data_type = Argument.data_type_string
        customer_name_argument.description = "Comma-separated list of customer names"
        scheme.add_argument(customer_name_argument)

        return scheme

    def validate_input(self, validation_definition):
        """If validate_input does not raise an Exception, the input is
        assumed to be valid. Otherwise it prints the exception as an error message
        when telling splunkd that the configuration is invalid.

        :param validation_definition: a ValidationDefinition object
        """

        customer_names = str(validation_definition.parameters["customer_names"])
        customer_names += ""
        if not customer_names:
            raise ValueError(
                "customer_names must be a comma-separated list of customer names"
            )

        pass

    def stream_events(self, inputs, ew):
        """
        :param inputs: an InputDefinition object
        :param ew: an EventWriter object
        """

        logger.debug("stream_events CALLED")

        # there should only be one input as we're
        # setting scheme.use_single_instance = False
        stanza = list(inputs.inputs.keys())[0]
        logger.debug(f"stanza name is {stanza}")

        # Get mod input params
        customer_names = str(inputs.inputs[stanza]["customer_names"])

        username, password = self._get_password(self.service, "ta_for_insightidr_realm")
        if password is None:
            message = "No credentials defined. Exiting"
            logger.error(message)
            return

        # url-decode the username
        username = username.replace("%40", "@")

        # split the password into password and secret values, separated by a dunder
        if "__" in password:
            password, secret = password.split("__")
        else:
            logger.error("No secret found in password")
            return

        session = rapid7lib.auth_via_okta(
            username=username, password=password, otp_secret=secret
        )

        for customer in customer_names.split(","):
            results = {}
            customer = customer.strip()
            logger.debug(f"Switching to customer {customer}")
            org_id = rapid7lib.switch_customer_by_name(session, customer)
            if org_id is None:
                logger.error(f"Could not find org_id for customer {customer}")
                continue

            # Get asset counts
            new_data = rapid7lib.get_asset_counts(
                session, org_id, customer_name=customer
            )
            results.update(new_data)
            event = Event()
            event.stanza = stanza
            event.data = json.dumps(results)
            ew.write_event(event)

            # Get basic detections
            results = rapid7lib.get_detections(session, org_id, customer_name=customer)
            event = Event()
            event.stanza = stanza
            event.data = json.dumps(results)
            ew.write_event(event)

            # Get user product access
            results = rapid7lib.get_user_product_access(
                session, org_id, customer_name=customer
            )
            event = Event()
            event.stanza = stanza
            event.data = json.dumps(results)
            ew.write_event(event)

            # Get event collection status
            results = rapid7lib.get_event_collection_status(
                session, org_id, customer_name=customer
            )
            event = Event()
            event.stanza = stanza
            event.data = json.dumps(results)
            ew.write_event(event)

            # Get usage stats
            results = rapid7lib.get_usage_stats(session, org_id, customer_name=customer)
            event = Event()
            event.stanza = stanza
            event.data = json.dumps(results)
            ew.write_event(event)

        logger.debug("Finished queries")

    def _get_password(self, service, realm):
        # logger.debug("_get_password CALLED")
        username = None
        password = None
        storage_passwords = service.storage_passwords
        for k in storage_passwords:
            # logger.debug("LOOPING...")
            pw_realm = str(k.content.get("realm"))
            if pw_realm == realm:
                username = k.content.get("username")
                password = k.content.get("clear_password")
                logger.info(f"username = {username}")
                return username, password

        return username, password


if __name__ == "__main__":
    sys.exit(MyScript().run(sys.argv))
