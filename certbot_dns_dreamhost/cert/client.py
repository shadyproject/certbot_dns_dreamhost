import logging

from certbot import errors
from certbot.plugins import dns_common
from dreamhostapi import DreamHostAPI
from dns import resolver
from tldextract import tldextract

DEFAULT_PROPAGATION_SECONDS = 600

ACME_TXT_PREFIX = "_acme-challenge"


class Authenticator(dns_common.DNSAuthenticator):
    """
    Authenticator class to handle a DNS-01 challenge for Dreamhost domains.
    """

    description = "Obtain certificates using a DNS TXT record for Dreamhost domains"
    record_ids_to_root_domain = dict()

    _domain = None

    def __init__(self, *args, **kwargs) -> None:
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add: callable) -> None:
        """
        Add required or optional argument for the cli of certbot

        :param add: method handling the argument adding to the cli
        """

        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=DEFAULT_PROPAGATION_SECONDS
        )
        add("credentials", help="Dreamhost credentials INI file.")
        add("key", help="Dreamhost API key (overwrites credentials file)")

    def more_info(self) -> str:
        """
        Get more information about this plugin.
        This method is used by certbot to show more info about this plugin.

        :return: string with more information about this plugin
        """

        return "This plugin configures a DNS TXT record to respond to a DNS-01 challenge using the Dreamhost DNS API."

    def _setup_credentials(self) -> None:
        """
        Setup Dreamhost key from credentials file
        """

        # If  cli param is provided we do not need a credentials file
        if self.conf("key"):
            return

        self._configure_file(
            "credentials", "Absolute path to Dreamhost credentials INI file"
        )

        dns_common.validate_file_permissions(self.conf("credentials"))
        self.credentials = self._configure_credentials(
            "credentials",
            "Dreamhost credentials INI file",
            {
                "key": "Dreamhost API key.",
            },
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        """
        Add the validation DNS TXT record to the provided Dreamhost domain.
        Moreover, it resolves the canonical name (CNAME) for the provided domain with the acme txt prefix.

        :param domain: the Dreamhost domain for which a TXT record will be created
        :param validation_name: the value to validate the dns challenge
        :param validation: the value for the TXT record

        :raise PluginError: if the TXT record can not be set or something goes wrong
        """

        client = self._get_dreamhost_client()

        propagation_seconds = self.conf("propagation_seconds")
        if propagation_seconds < 600:
            logging.warning(
                "The propagation time is less than Dreamhost DNS TTL minimum of 600 seconds. Subsequent "
                "challenges for same domain may fail. Try increasing the propagation time if you encounter "
                "issues."
            )

        # replace wildcard in domain
        domain = domain.replace("*", "")
        domain = f"{ACME_TXT_PREFIX}.{domain}"

        try:
            # follow all CNAME and DNAME records
            canonical_name = resolver.canonical_name(domain)
        except (resolver.NoAnswer, resolver.NXDOMAIN):
            canonical_name = domain

        extract_result = tldextract.extract(canonical_name.to_text())
        root_domain = f"{extract_result.domain}.{extract_result.suffix}"
        name = extract_result.subdomain

        try:
            self.record_ids_to_root_domain[validation] = (
                client.dns.add_record(
                    record=f"{name}.{root_domain}", type="TXT", value=validation
                ),
                root_domain,
            )

        except Exception as e:
            raise errors.PluginError(e)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        """
        Delete the TXT record of the provided Dreamhost domain.

        :param domain: the Dreamhost domain for which the TXT record will be deleted
        :param validation_name: the value to validate the dns challenge
        :param validation: the value for the TXT record

        :raise PluginError:  if the TXT record can not be deleted or something goes wrong
        """

        # get the record id with the TXT record
        record_id = self.record_ids_to_root_domain[validation][0]
        root_domain = self.record_ids_to_root_domain[validation][1]

        try:
            if not self._get_dreamhost_client().dns.remove_record(
                record=root_domain, type="TXT", value=validation
            ):
                raise errors.PluginError(
                    "TXT for domain {} was not deleted".format(domain)
                )
        except Exception as e:
            raise errors.PluginError(e)

    def _get_dreamhost_client(self) -> DreamHostAPI:
        """
        Create a new dreamhostapi client with the provided API key and secret.

        :return: the created dreamhostapi object
        """

        key = self.conf("key") or self.credentials.conf("key")

        return DreamHostAPI(key)
